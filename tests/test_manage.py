import contextlib
import io
import os
import sqlite3
import subprocess
import tarfile
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import patch

import manage


class ManagementTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        root = Path(self.tmp.name)
        self.data = root / 'data'
        self.data.mkdir()
        self.config = root / 'etc' / 'cf-vps.env'
        self.app = root / 'opt'
        self.app.mkdir()
        (self.app / 'server.py').write_text('# fixture')
        self.unit = root / 'cf-vps.service'
        self.unit.write_text('# fixture')
        self.backups = root / 'backups'
        self.patches = [patch.object(manage, 'APP', self.app), patch.object(manage, 'CONFIG', self.config),
                        patch.object(manage, 'UNIT', self.unit), patch.object(manage, 'BACKUPS', self.backups),
                        patch.object(manage, 'COMMAND', root / 'cf-vps'),
                        patch.object(manage, 'PREVIOUS', root / 'previous'),
                        patch.object(manage, 'RELEASES', root / 'releases')]
        for p in self.patches:
            p.start()
        manage.write_config({'CFVPS_HOST':'127.0.0.1', 'CFVPS_PORT':'8787',
                             'CFVPS_PASSWORD':'test-password-12345678', 'CFVPS_DATA':str(self.data)})
        self.db = sqlite3.connect(self.data / 'scan.db')
        self.db.execute('PRAGMA journal_mode=WAL')
        self.db.executescript('CREATE TABLE jobs(id TEXT); CREATE TABLE results(ip TEXT);')
        self.db.execute('INSERT INTO jobs VALUES (?)', ('checkpoint-job',))
        self.db.commit()
        self.output = contextlib.redirect_stdout(io.StringIO())
        self.output.__enter__()

    def tearDown(self):
        self.db.close()
        self.output.__exit__(None, None, None)
        for p in reversed(self.patches):
            p.stop()
        self.tmp.cleanup()

    def test_config_roundtrip_permissions_and_newline_rejection(self):
        config = manage.read_config()
        config['CFVPS_PASSWORD'] = 'spaces $() "quotes" \\ literal # chars'
        manage.write_config(config)
        self.assertEqual(manage.read_config(), config)
        self.assertEqual(self.config.stat().st_mode & 0o777, 0o600)
        config['CFVPS_PASSWORD'] = 'bad\nCFVPS_HOST=0.0.0.0'
        with self.assertRaises(ValueError):
            manage.write_config(config)
        self.assertNotIn('bad', self.config.read_text())

    def test_online_backup_includes_committed_wal(self):
        self.db.execute('INSERT INTO results VALUES (?)', ('8.8.8.8',))
        self.db.commit()
        with patch.object(manage, 'run', side_effect=AssertionError('backup must not stop service')):
            archive = manage.backup()
        self.assertEqual(archive.stat().st_mode & 0o777, 0o600)
        self.assertEqual(self.backups.stat().st_mode & 0o777, 0o700)
        with tarfile.open(archive) as tar:
            self.assertEqual(set(tar.getnames()), {'scan.db','cf-vps.env','manifest.json'})
            restored = Path(self.tmp.name) / 'snapshot.db'
            restored.write_bytes(tar.extractfile('scan.db').read())
        with sqlite3.connect(restored) as db:
            self.assertEqual(db.execute('SELECT ip FROM results').fetchone()[0], '8.8.8.8')
        self.assertEqual(self.db.execute('SELECT COUNT(*) FROM jobs').fetchone()[0], 1)

    def test_public_and_port_keep_credentials(self):
        before = manage.read_config()
        with patch.object(manage, 'restart'), patch.object(manage, 'info'), patch.object(manage.shutil, 'which', return_value=None):
            manage.set_access(True)
            self.assertEqual(manage.read_config()['CFVPS_HOST'], '0.0.0.0')
            manage.set_port('9999')
            manage.set_access(False)
        config = manage.read_config()
        self.assertEqual(config['CFVPS_PORT'], '9999')
        self.assertEqual(config['CFVPS_HOST'], '127.0.0.1')
        self.assertEqual(config['CFVPS_PASSWORD'], before['CFVPS_PASSWORD'])
        with self.assertRaises(ValueError):
            manage.set_port('70000')

    def test_failed_restart_rolls_back_config(self):
        before = manage.read_config()
        with patch.object(manage, 'restart', side_effect=ValueError('port busy')), patch.object(manage, 'run') as run:
            with self.assertRaises(ValueError):
                manage.set_port('9999')
        self.assertEqual(manage.read_config(), before)
        run.assert_called_once_with('systemctl', 'restart', 'cf-vps', check=False)

    def test_restore_replaces_data_and_keeps_safety_backup(self):
        archive = manage.backup()
        self.db.execute("UPDATE jobs SET id='later-job'")
        self.db.commit()
        self.db.close()
        account = types.SimpleNamespace(pw_uid=os.getuid(), pw_gid=os.getgid())
        with patch('builtins.input', return_value='RESTORE'), patch.object(manage, 'active', return_value=True), patch.object(manage, 'run') as run, patch.object(manage.pwd, 'getpwnam', return_value=account):
            manage.restore(archive)
        with sqlite3.connect(self.data / 'scan.db') as db:
            self.assertEqual(db.execute('SELECT id FROM jobs').fetchone()[0], 'checkpoint-job')
        self.assertEqual(len(list(self.backups.glob('*.tar.gz'))), 2)
        self.assertEqual(run.call_args_list[0].args, ('systemctl','stop','cf-vps'))
        self.assertEqual(run.call_args_list[-1].args, ('systemctl','start','cf-vps'))

    def test_restore_rejects_symlinks(self):
        archive = Path(self.tmp.name) / 'bad.tar.gz'
        with tarfile.open(archive, 'w:gz') as tar:
            entry = tarfile.TarInfo('manifest.json')
            entry.type = tarfile.SYMTYPE
            entry.linkname = '/etc/passwd'
            tar.addfile(entry)
        with self.assertRaises(ValueError), patch.object(manage, 'run') as run:
            manage.restore(archive)
        run.assert_not_called()

    def test_uninstall_preserves_records_and_manager(self):
        self.db.close()
        with patch('builtins.input', return_value='DELETE'), patch.object(manage, 'run'):
            manage.uninstall()
        self.assertFalse(self.app.exists())
        self.assertFalse(self.unit.exists())
        self.assertTrue(self.config.exists())
        self.assertTrue((self.data / 'scan.db').exists())
        self.assertEqual(len(list(self.backups.glob('*.tar.gz'))), 1)

    def test_uninstall_refuses_to_remove_running_service(self):
        with patch('builtins.input', return_value='DELETE'), patch.object(manage, 'run'), patch.object(manage, 'active', return_value=True):
            with self.assertRaises(ValueError):
                manage.uninstall()
        self.assertTrue(self.app.exists())
        self.assertTrue(self.unit.exists())
        self.assertTrue((self.data / 'scan.db').exists())

    def test_public_opens_enabled_ufw(self):
        status = subprocess.CompletedProcess(['ufw', 'status'], 0, 'Status: active\n', '')
        with patch.object(manage, 'restart'), patch.object(manage, 'info'), patch.object(manage.shutil, 'which', return_value='/usr/sbin/ufw'), patch.object(manage.subprocess, 'run', return_value=status), patch.object(manage, 'run') as run:
            manage.set_access(True)
        run.assert_called_once_with('ufw', 'allow', '8787/tcp')

    def test_menu_exit(self):
        with patch('builtins.input', return_value='0'):
            manage.menu()

    def test_retention_keeps_upgrade_snapshot(self):
        first=manage.backup(quiet=True)
        pointer=self.app/'.rollback-backup'
        pointer.write_text(str(first))
        manage.backup(quiet=True)
        manage.backup(quiet=True)
        manage.retention('1')
        self.assertTrue(first.exists())
        self.assertEqual(len(list(self.backups.glob('*.tar.gz'))),2)

    def test_manual_code_and_data_rollback(self):
        snapshot=manage.backup(quiet=True)
        self.db.close()
        current=Path(self.tmp.name)/'current-release'
        self.app.rename(current)
        (current/'.rollback-backup').write_text(str(snapshot))
        previous=Path(self.tmp.name)/'old-release'
        previous.mkdir()
        (previous/'server.py').write_text('# old server')
        (previous/'manage.py').write_text('# old manager')
        self.app.symlink_to(current)
        manage.PREVIOUS.symlink_to(previous)
        with sqlite3.connect(self.data/'scan.db') as db:
            db.execute("UPDATE jobs SET id='newer-job'")
        account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
        with patch('builtins.input',return_value='ROLLBACK'),patch.object(manage,'run'),patch.object(manage,'active',return_value=False),patch.object(manage.pwd,'getpwnam',return_value=account):
            manage.rollback()
        self.assertEqual(self.app.resolve(),previous)
        with sqlite3.connect(self.data/'scan.db') as db:
            self.assertEqual(db.execute('SELECT id FROM jobs').fetchone()[0],'checkpoint-job')
        self.assertFalse(manage.PREVIOUS.exists())

    def test_certificate_failure_has_recovery_instructions(self):
        failure=subprocess.CalledProcessError(1,['certbot'])
        with patch.object(manage,'run',side_effect=failure),contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(ValueError) as error:
                manage.request_domain_certificate('scan.example.com')
        self.assertIn('灰云',str(error.exception))
        self.assertIn('cf-vps domain scan.example.com',str(error.exception))
        self.assertIn('AAAA',str(error.exception))
        self.assertIn('无需重装',str(error.exception))

    def test_certificate_request_uses_existing_webroot(self):
        with patch.object(manage,'run') as run,contextlib.redirect_stdout(io.StringIO()):
            manage.request_domain_certificate('scan.example.com')
        run.assert_called_once_with('certbot','certonly','--webroot','-w','/var/www/html','-d','scan.example.com','--non-interactive','--agree-tos','--register-unsafely-without-email')

    def test_domain_validation_precedes_side_effects(self):
        with patch.object(manage,'run') as run:
            with self.assertRaises(ValueError):manage.configure_domain('bad.example.com;touch /tmp/test')
        run.assert_not_called()


    def test_provider_cache_is_backed_up_and_restored(self):
        import json
        cached={'version':1,'custom':[],'cache':{'vultr':{'networks':['8.8.8.0/30'],'updated_at':123,'source':'fixture'}}}
        provider=self.data/'providers.json'
        provider.write_text(json.dumps(cached))
        archive=manage.backup(quiet=True)
        self.db.close()
        provider.write_text(json.dumps({'version':1,'custom':[],'cache':{}}))
        account=types.SimpleNamespace(pw_uid=os.getuid(),pw_gid=os.getgid())
        with patch('builtins.input',return_value='RESTORE'),patch.object(manage,'run'),patch.object(manage,'active',return_value=False),patch.object(manage.pwd,'getpwnam',return_value=account):
            manage.restore(archive)
        self.assertEqual(json.loads(provider.read_text()),cached)
        self.assertEqual(provider.stat().st_mode&0o777,0o600)

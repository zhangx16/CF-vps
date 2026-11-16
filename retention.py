"""Periodic result retention; never constructs a Manager or changes running jobs."""
import os
from pathlib import Path
from engine import prune_retention

if __name__ == '__main__':
    prune_retention(Path(os.environ.get('CFVPS_DATA', '/var/lib/cf-vps')) / 'scan.db')

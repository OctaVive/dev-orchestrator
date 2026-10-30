#!/usr/bin/env python3
"""Run M08 isolated parsing/build/admission plus the M07 pipeline regression."""
import os, runpy
from pathlib import Path
if os.environ.get('M08_LAB_APPROVED')!='YES-I-AUTHORIZE-CONFIG-LAB':
    raise SystemExit('explicit disposable M08 lab opt-in required')
os.environ.update(M08_LAB='1',M07_LAB_APPROVED='YES-I-AUTHORIZE-BUILD-LAB')
runpy.run_path(str(Path(__file__).resolve().parents[1]/'build/lab.py'),run_name='__main__')

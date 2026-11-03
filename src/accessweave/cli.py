import argparse
import json
from pathlib import Path

from .analyzer import analyze_inventory, relationship_edges


def main():
    p=argparse.ArgumentParser(); p.add_argument("inventory", type=Path); p.add_argument("--output", type=Path)
    a=p.parse_args()
    data=json.loads(a.inventory.read_text(encoding="utf-8"))
    result={"findings":analyze_inventory(data),"edges":relationship_edges(data)}
    text=json.dumps(result,indent=2)
    if a.output: a.output.write_text(text+"\n",encoding="utf-8")
    print(text)
if __name__=="__main__": main()

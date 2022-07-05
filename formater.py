import json
import yaml
import re

def saveJson2file(info, path, format="json"):
    """
    Args:
        info (free text | list | dictonary): free text or stractured format to dump into file
        path (str): path on file system to open file
        format (str): JSON|YAML|free format. Defaults to None.
    """
    try:
        with open(path, "w") as f:
            if re.match("[Jj]|js(on)?|J(SON|son)",format):
                print(f"[*] creating json file")
                f.write(json.dumps(info, indent=4))
                print(f"[Info] successfuly creating json file at {path}")

            elif re.match("[Yy]|Y(AML|aml)|y(a?)ml",format):
                f.write(yaml.dump(info))


                print(f"[Info] succsesfuly creating file at {path}")
    except Exception as e:
        print(f"[Error] error when saving file: {e}")


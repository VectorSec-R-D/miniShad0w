import sys
  
# adding Folder_2 to the system path
sys.path.insert(0, "../")

import tools

__all__ = tools.get_commands()
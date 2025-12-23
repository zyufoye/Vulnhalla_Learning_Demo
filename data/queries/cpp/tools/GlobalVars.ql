import cpp

from GlobalOrNamespaceVariable g
select g.getName() as global_var_name, g.getLocation().getFile() as file, g.getLocation().getStartLine() as start_line, g.getLocation().getEndLine() as end_line

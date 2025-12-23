import cpp

from Macro m
select m.getName() as macro_name, "#define " + m.getHead() + " " + m.getBody() as body

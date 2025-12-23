import cpp

string get_caller(Function c){
  if exists(FunctionCall d | c.getACallToThisFunction() = d)
  then result = c.getACallToThisFunction().getEnclosingFunction().getLocation().getFile() + ":" + c.getACallToThisFunction().getEnclosingFunction().getLocation().getStartLine()
  else result = ""
}


from Function f
select f.getName() as function_name, f.getLocation().getFile() as file, f.getLocation().getStartLine() as start_line, file + ":" + start_line as function_id, f.getBlock().getLocation().getEndLine() as end_line, get_caller(f) as caller_id


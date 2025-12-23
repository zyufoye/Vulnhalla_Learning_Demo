import cpp

private predicate isNamespaceEntity(NameQualifyingElement n) { n instanceof Namespace }
private predicate isUserTypeEntity(NameQualifyingElement n) { n instanceof UserType }
private predicate isClassEntity(NameQualifyingElement n) { n instanceof Class }


private int getEndLine(NameQualifyingElement n) {
  exists (Namespace c | c = n and result = max(c.getADeclaration().getLocation().getEndLine()))
  or
  // Anonymus structs. This will get the real end line
  exists (Class c | c = n and c.getName() = "(unnamed class/struct/union)" and exists (TypedefType u | u.getUnderlyingType() instanceof Class and u.getUnderlyingType() = c and result = u.getLocation().getStartLine()))
  or
  exists (Class c | c = n and result = max(c.getAMember().getLocation().getEndLine()))
  or
  exists (UserType u | u = n and result = max(u.getADeclaration().getLocation().getEndLine()))
}

private string getType(NameQualifyingElement c) {
  isNamespaceEntity(c) and result = "NameSapce"
  or
  isClassEntity(c) and result = "Class"
  or
  isUserTypeEntity(c) and result = "UserType"
}

private string getName(NameQualifyingElement n) {
  // Anonymus structs
  n.getName() = "(unnamed class/struct/union)" and exists (TypedefType u | u.getUnderlyingType() instanceof Class and u.getUnderlyingType() = n and result = u.getName())
  or
  result = n.getName()
}

private string getSimpleName(NameQualifyingElement n) {
  isNamespaceEntity(n) and result = ""
  or
  // Anonymus structs
  n.getName() = "(unnamed class/struct/union)" and exists (TypedefType u | u.getUnderlyingType() instanceof Class and u.getUnderlyingType() = n and result = u.getSimpleName())
  or
  exists (UserType u | u = n and result = u.getSimpleName())
}

from NameQualifyingElement c
where isNamespaceEntity(c) or isUserTypeEntity(c)
select getType(c) as type, getName(c) as name, c.getLocation().getFile() as file, c.getLocation().getStartLine() as start_line, getEndLine(c) as end_line, getSimpleName(c) as simple_name

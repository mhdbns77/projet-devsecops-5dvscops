package main

# Refuser si runAsNonRoot n'est pas explicitement défini à true
deny[msg] {
  input.kind == "Deployment"
  container := input.spec.template.spec.containers[_]
  
  # On vérifie si securityContext.runAsNonRoot est absent ou faux
  not container.securityContext.runAsNonRoot == true
  
  msg := sprintf("Le conteneur '%v' doit s'exécuter en non-root (ajouter securityContext.runAsNonRoot: true)", [container.name])
}

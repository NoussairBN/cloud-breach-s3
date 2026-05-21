# PFS - Sécurité Cloud & Durcissement (IaC)

Ce projet traite de la remédiation et du durcissement d'une infrastructure AWS initialement vulnérable (scénario `cloud_breach_s3`).

## Structure du dépôt
- `/terraform` : Code source Terraform durci appliquant le principe du moindre privilège.
- `/image_durci` : Captures d'écran des preuves d'attaque (PoC) et de la validation de la remédiation.

## Durcissement appliqué
- Suppression de la politique IAM `AmazonS3FullAccess` au profit d'une politique restreinte.
- Restriction des accès S3 via l'utilisation de `aws_iam_role_policy_attachment`.

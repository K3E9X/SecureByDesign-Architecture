# Présentation PowerPoint - Principes Fondamentaux de l'Architecture Cybersécurité

---

## Slide 1 : Page de titre

**PRINCIPES FONDAMENTAUX DE L'ARCHITECTURE CYBERSÉCURITÉ**

*Les 6 piliers de la sécurité des systèmes d'information*

---

## Slide 2 : Agenda

### Au programme

1. Introduction et contexte
2. Defense in Depth
3. Least Privilege
4. Separation of Duties
5. Secure by Design
6. Keep It Simple, Stupid (KISS)
7. Security by Obscurity (à éviter)
8. Mise en pratique
9. Conclusion

**Durée estimée :** 45-60 minutes

---

## Slide 3 : Pourquoi ces principes ?

### Contexte actuel

- **Augmentation des cyberattaques** : +38% en 2025
- **Coût moyen d'une violation** : 4,45M$ (IBM, 2024)
- **Temps moyen de détection** : 277 jours
- **Transformation digitale** : Surface d'attaque en expansion
- **Pénurie de talents** : 3,5M postes non pourvus

### Solution

**Des principes éprouvés pour construire des systèmes résilients**

---

## Slide 4 : Les 6 principes

```
┌─────────────────────────────────────────────────────┐
│                                                     │
│  1. DEFENSE IN DEPTH       4. SECURE BY DESIGN     │
│     (Défense en profondeur)   (Sécurité dès le     │
│                                début)               │
│                                                     │
│  2. LEAST PRIVILEGE        5. KISS                 │
│     (Moindre privilège)       (Simplicité)         │
│                                                     │
│  3. SEPARATION OF DUTIES   6. PAS Security by      │
│     (Séparation des tâches)   Obscurity           │
│                                                     │
└─────────────────────────────────────────────────────┘
```

---

## PARTIE 1 : DEFENSE IN DEPTH

---

## Slide 5 : Defense in Depth - Concept

### Définition

**Stratégie de sécurité multi-couches**

> "Si une couche échoue, les autres continuent à protéger"

### Origine

- Concept militaire ancien (châteaux médiévaux)
- Adapté à la cybersécurité années 1990
- Standard NIST, ANSSI, ISO 27001

### Principe clé

**Pas de point unique de défaillance**

---

## Slide 6 : Les 6 couches de défense

```
┌─────────────────────────────────────────┐
│ 1. UTILISATEUR                          │
│    • Formation anti-phishing            │
│    • MFA obligatoire                    │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ 2. RÉSEAU                               │
│    • Firewall / IDS-IPS                 │
│    • Segmentation (VLAN, DMZ)           │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ 3. HÔTE                                 │
│    • Antivirus / EDR                    │
│    • Hardening OS                       │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ 4. APPLICATION                          │
│    • WAF                                │
│    • Validation inputs                  │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ 5. DONNÉES                              │
│    • Chiffrement at rest                │
│    • DLP                                │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ 6. GOUVERNANCE                          │
│    • Politiques de sécurité             │
│    • Audit et conformité                │
└─────────────────────────────────────────┘
```

---

## Slide 7 : Exemple concret - Application bancaire

### Architecture multi-couches

| Couche | Protection | Technologie |
|--------|------------|-------------|
| **Périmètre** | Anti-DDoS, Firewall | Cloudflare, F5 |
| **DMZ** | WAF, Load Balancer | ModSecurity, HAProxy |
| **Application** | Authentification forte | OAuth 2.0 + MFA |
| **Données** | Chiffrement AES-256 | TDE, Vault |
| **Monitoring** | SIEM, SOC 24/7 | Splunk, QRadar |

### Résultat

**5 barrières à franchir pour un attaquant**

---

## Slide 8 : Defense in Depth - Bénéfices et limites

### Avantages ✓

- Résilience accrue
- Détection multiple des attaques
- Ralentissement des attaquants
- Confinement des incidents

### Limites ✗

- Coût d'investissement élevé
- Complexité de gestion
- Impact potentiel sur performances
- Risque de faux sentiment de sécurité

### Best Practice

**Diversifier les technologies et surveiller toutes les couches**

---

## PARTIE 2 : LEAST PRIVILEGE

---

## Slide 9 : Least Privilege - Concept

### Définition

> "Un utilisateur, programme ou processus doit avoir uniquement les accès strictement nécessaires pour accomplir sa fonction"

### Citation fondatrice

**Jerome Saltzer, 1974**

### Objectifs

1. Réduire la surface d'attaque
2. Limiter les dommages en cas de compromission
3. Conformité réglementaire (RGPD, ISO 27001)

---

## Slide 10 : Principe de moindre privilège en action

### Mauvaise pratique ❌

```
Tous les utilisateurs = Administrateurs
→ Risque MAXIMAL
```

### Bonne pratique ✅

```
┌─────────────────────────────────────┐
│ Utilisateurs standards              │
│ Accès : Ressources personnelles     │
│ Permissions : Lecture/Écriture      │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ Administrateurs                     │
│ Compte 1 : Usage quotidien (std)   │
│ Compte 2 : Admin (séparé)          │
│ Élévation : JIT (Just-In-Time)     │
└─────────────────────────────────────┘

┌─────────────────────────────────────┐
│ Applications                        │
│ Compte DB : SELECT uniquement       │
│ Pas de DROP/DELETE en prod          │
└─────────────────────────────────────┘
```

---

## Slide 11 : Mise en œuvre - 4 étapes

### 1. Inventaire
- Recenser tous les comptes, rôles, permissions
- Identifier propriétaires et justifications

### 2. Analyse
- Détecter les sur-privilèges
- Identifier comptes orphelins
- Analyser accès réels vs accordés

### 3. Remédiation
- Révoquer accès inutiles
- Créer rôles granulaires (RBAC)
- Implémenter PAM

### 4. Surveillance
- Monitoring des privilèges
- Alertes sur usage anormal
- Revue régulière des accès

---

## Slide 12 : Exemple RBAC

### Modèle basé sur les rôles

```
UTILISATEURS
   │
   ├─► LECTEUR
   │   └─► Permissions : READ
   │
   ├─► ÉDITEUR
   │   └─► Permissions : READ, WRITE
   │
   └─► ADMINISTRATEUR
       └─► Permissions : READ, WRITE, DELETE, ADMIN
```

### Règle d'or

**Accorder le minimum + Élévation temporaire si besoin**

---

## Slide 13 : KPIs à surveiller

| Indicateur | Objectif |
|------------|----------|
| **Comptes à privilèges** | < 5% du total |
| **Taux de sur-privilèges** | < 10% |
| **Délai de révocation** | < 24h (départ employé) |
| **Couverture PAM** | 100% comptes admin |
| **Incidents liés aux privilèges** | Tendance baisse |

---

## PARTIE 3 : SEPARATION OF DUTIES

---

## Slide 14 : Separation of Duties - Concept

### Définition

**Diviser les responsabilités critiques entre plusieurs personnes**

### Principe fondamental

> "Aucune personne ne doit avoir un contrôle complet sur une transaction critique du début à la fin"

### Objectifs

1. Prévention de la fraude (nécessite collusion)
2. Détection d'erreurs (revue croisée)
3. Réduction des risques humains
4. Conformité réglementaire (SOX, RGPD)

---

## Slide 15 : Exemple - Processus financier

### Sans SoD ❌

```
Une seule personne peut :
1. Créer une facture
2. L'approuver
3. La payer

→ RISQUE DE FRAUDE ÉLEVÉ
```

### Avec SoD ✅

| Rôle | Responsabilité |
|------|----------------|
| **Demandeur** | Crée la demande d'achat |
| **Approbateur** | Valide la demande |
| **Acheteur** | Passe la commande |
| **Réceptionnaire** | Réceptionne marchandise |
| **Payeur** | Effectue le paiement |

**→ Nécessite 5 personnes en collusion pour frauder**

---

## Slide 16 : SoD en IT - Déploiement en production

```
┌─────────────────────────────────────┐
│ DÉVELOPPEUR                         │
│ • Écrit le code                     │
│ • Teste en dev                      │
│ • Crée Pull Request                 │
│ ✗ NE PEUT PAS déployer en prod     │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│ LEAD DEVELOPER                      │
│ • Code review                       │
│ • Approuve PR                       │
│ ✗ NE PEUT PAS déployer              │
└─────────────────────────────────────┘
           ↓
┌─────────────────────────────────────┐
│ DEVOPS / SRE                        │
│ • Valide tests automatisés          │
│ • Exécute le déploiement            │
│ ✗ NE PEUT PAS modifier le code     │
└─────────────────────────────────────┘
```

---

## Slide 17 : Matrice de séparation

| Tâche | Admin Réseau | RSSI | Auditeur |
|-------|--------------|------|----------|
| **Créer règle FW** | ✓ | ✗ | ✗ |
| **Approuver règle** | ✗ | ✓ | ✗ |
| **Implémenter** | ✓ | ✗ | ✗ |
| **Vérifier** | ✗ | ✓ | ✗ |
| **Auditer** | ✗ | ✗ | ✓ |

### Principe

**Aucune personne ne cumule création + approbation + audit**

---

## Slide 18 : Procédure "Break-Glass"

### Pour les urgences uniquement

```
1. Identification urgence CRITIQUE
2. Notification automatique RSSI + Management
3. Utilisation compte "break-glass" (MFA fort)
4. Enregistrement vidéo + logs détaillés
5. Durée limitée (2h maximum)
6. Revue obligatoire sous 24h
7. Documentation complète
8. Analyse post-mortem
```

### Règle

**Traçabilité maximale + Revue systématique**

---

## PARTIE 4 : SECURE BY DESIGN

---

## Slide 19 : Secure by Design - Concept

### Définition

**Intégrer la sécurité dès les premières phases de conception**

### Citation

> "It is far easier to design security into a system than to add it later"
> — Gary McGraw

### Principe clé

**Sécurité = Fondation, pas une fonctionnalité**

---

## Slide 20 : Coût de la sécurité selon la phase

```
PHASE                  COÛT RELATIF
────────────────────────────────────
Conception                  1x
Développement              10x
Test                      100x
Production               1000x

Source : IBM System Science Institute
```

### Conclusion

**Intégrer la sécurité dès la conception = 1000x moins coûteux !**

---

## Slide 21 : Shift-Left Security

### Ancien modèle ❌

```
Conception → Dev → Test → SÉCURITÉ → Production
                            ↑
                    Bugs coûteux à corriger
```

### Nouveau modèle ✅

```
Conception + Sécurité
    ↓
Développement + Sécurité (SAST/SCA)
    ↓
Test + Sécurité (DAST/Pentest)
    ↓
Production + Monitoring
```

**Sécurité intégrée à chaque étape**

---

## Slide 22 : Méthodologie - 6 phases

### Phase 1 : Analyse des exigences
- Classification des données
- Analyse de conformité (RGPD, etc.)
- Exigences de sécurité

### Phase 2 : Threat Modeling
- Méthode STRIDE
- Identification des menaces
- Évaluation des risques

### Phase 3 : Architecture sécurisée
- Zero Trust Architecture
- Fail Secure (échec sécurisé)
- Minimisation des données

---

## Slide 23 : Méthodologie - 6 phases (suite)

### Phase 4 : Développement sécurisé
- Code review obligatoire
- SAST (analyse statique)
- Gestion sécurisée des secrets
- Validation des inputs

### Phase 5 : Tests de sécurité
- SAST / DAST / SCA
- Dependency scanning
- Pentest avant release

### Phase 6 : Déploiement sécurisé
- Security Readiness Review
- Chiffrement activé
- Logs et monitoring configurés

---

## Slide 24 : STRIDE Threat Modeling

| Menace | Description | Exemple | Contre-mesure |
|--------|-------------|---------|---------------|
| **S**poofing | Usurpation identité | Faux login | MFA |
| **T**ampering | Modification données | SQL injection | Prepared statements |
| **R**epudiation | Déni d'action | Pas de logs | Audit trail |
| **I**nfo Disclosure | Fuite données | Data non chiffrées | TLS + encryption |
| **D**enial of Service | Déni de service | DDoS | Rate limiting |
| **E**levation Privilege | Élévation privilèges | Exploit | Least privilege |

---

## Slide 25 : Pyramide des tests de sécurité

```
          ┌─────────────┐
          │  Pentest    │ ← Manuel, périodique
          │  Red Team   │
          └─────────────┘
       ┌──────────────────┐
       │  DAST / Fuzzing  │ ← Auto, CI/CD
       └──────────────────┘
    ┌──────────────────────┐
    │  SAST / SCA          │ ← Auto, commit
    └──────────────────────┘
  ┌────────────────────────────┐
  │  Unit Tests sécurité       │ ← Développeurs
  └────────────────────────────┘
```

**Automatiser au maximum**

---

## Slide 26 : Bénéfices mesurables

| Métrique | Avant | Après |
|----------|-------|-------|
| **Vulnérabilités en prod** | 50/release | 5/release |
| **Coût correction** | 10 000€ | 1 000€ |
| **Time to remediation** | 30 jours | 3 jours |
| **Incidents sécurité** | 12/an | 2/an |
| **Conformité audits** | 60% | 95% |

**ROI : Réduction des coûts et des risques**

---

## PARTIE 5 : KEEP IT SIMPLE, STUPID (KISS)

---

## Slide 27 : KISS - Concept

### Définition

**La simplicité doit être un objectif clé dans la conception**

### Citation

> "Complexity is the enemy of security"
> — Bruce Schneier, Cryptographe

### Pourquoi ?

- Plus de complexité = Plus de bugs
- Plus de code = Plus de surface d'attaque
- Plus de composants = Plus de vulnérabilités
- Difficile à auditer et maintenir

---

## Slide 28 : Statistiques

### Impact de la complexité

```
Étude Université de Californie :
• 1000 lignes de code = 15-50 bugs
• Dont 1-5 bugs de sécurité exploitables

Étude NIST :
• 70% des vulnérabilités = code complexe inutile
• Simplification = -40% coûts maintenance
```

### Règle

**Complexité inutile = Vulnérabilités évitables**

---

## Slide 29 : Exemple - Authentification

### Mauvaise pratique ❌

```python
# Cryptographie custom (DANGEREUX!)
def custom_hash_password(password, salt):
    # 200 lignes de logique maison
    # Probablement cassable
    pass
```

### Bonne pratique ✅

```python
from werkzeug.security import generate_password_hash

# Simple, sûr, maintenu par la communauté
hashed = generate_password_hash(password)
```

**Utiliser des bibliothèques éprouvées**

---

## Slide 30 : Règles KISS en cybersécurité

### 1. Minimiser la surface d'attaque
- Seulement les endpoints nécessaires
- Réduire les dépendances
- Supprimer le code mort

### 2. Architecture simple
- Éviter les couches d'abstraction inutiles
- 3-5 composants max si possible
- Facile à comprendre et débugger

### 3. Configuration minimale
- Valeurs par défaut sécurisées
- Variables d'environnement
- Documentation claire

---

## Slide 31 : Checklist KISS

```
Avant d'ajouter une fonctionnalité :

□ Est-ce vraiment nécessaire ?
□ Existe-t-il une solution plus simple ?
□ Puis-je utiliser un composant existant ?
□ Cela augmente-t-il la surface d'attaque ?
□ Sera-ce facile à maintenir dans 2 ans ?
□ Un nouvel arrivant peut-il comprendre rapidement ?
□ La documentation est-elle simple ?

Si NON à une question → RECONSIDÉRER
```

---

## Slide 32 : KISS ne signifie PAS...

### ❌ Ce que KISS n'est PAS

- Sacrifier la sécurité
- Ne pas utiliser de patterns éprouvés
- Écrire du code non maintenable
- Ignorer les best practices

### ✅ Ce que KISS signifie

- Choisir la solution la plus simple qui fonctionne
- Éviter la sur-ingénierie
- Préférer la clarté à l'ingéniosité
- Réduire la complexité accidentelle

---

## PARTIE 6 : SECURITY BY OBSCURITY

---

## Slide 33 : Security by Obscurity - À ÉVITER

### Définition

**Stratégie qui repose sur le secret du fonctionnement pour assurer la sécurité**

### Position de la communauté

> "Security through obscurity is not security"

### Principe de Kerckhoffs (1883)

**"Le système doit être sûr même si tout est public, sauf la clé"**

---

## Slide 34 : Pourquoi c'est dangereux

### 1. Faux sentiment de sécurité

```python
# URL "secrète" sans authentification
@app.route('/x8f9h3k2j')  # Admin caché
def secret_admin():
    return admin_panel()

# Problèmes :
# • Découvrable par fuzzing
# • Visible dans le code frontend
# • Erreur humaine (commit Git)
```

### 2. Sécurité = 0 dès que découvert

**Pas de plan B si le secret est révélé**

---

## Slide 35 : Échecs historiques

### Exemples célèbres

| Système | Année | Résultat |
|---------|-------|----------|
| **CSS (DVD)** | 1999 | Algorithme secret reverse-engineered → Tout le système tombé |
| **WEP (WiFi)** | 2001 | Protocole "secret" cassé → Remplacé par WPA |
| **Kryptos** | 2000s | Crypto propriétaire cassée → AES (public) toujours sûr |

### Leçon

**Algorithmes publics et audités > Secrets obscurs**

---

## Slide 36 : Quand l'obscurité a un rôle (limité)

### Acceptable comme couche supplémentaire ✓

```
• Changer port SSH (22 → 2222)
  → Réduit le bruit des scans automatisés
  MAIS + Clés SSH + Firewall + Fail2ban

• Masquer versions serveur
  → N'informe pas des CVE exploitables
  MAIS + Patching régulier

• Honeypots
  → Détecte les scans
  MAIS + Vraie défense en place
```

### JAMAIS comme défense principale ✗

---

## Slide 37 : Vraie sécurité vs Obscurité

### Obscurité ❌

```
URL secrète sans authentification
→ Découverte par fuzzing
→ Sécurité = 0
```

### Vraie sécurité ✅

```
Endpoint public MAIS :
• Authentification JWT
• Autorisation RBAC
• Rate limiting
• Audit logging
• HTTPS (TLS 1.3)

→ Sécurité maintenue même si URL connue
```

---

## Slide 38 : Alternatives recommandées

| Au lieu de... | Utiliser... |
|---------------|-------------|
| URL secrète | OAuth 2.0 / JWT |
| Port non-standard seul | Firewall + whitelist IP + clés SSH |
| Algorithme custom | AES, RSA (standards publics) |
| Security questions | TOTP / FIDO2 / WebAuthn |
| Obfuscation code | Chiffrement données sensibles |

### Règle d'or

**Standards publics et audités + Secrets changeables (clés)**

---

## PARTIE 7 : MISE EN PRATIQUE

---

## Slide 39 : Cas pratique - Audit d'architecture

### Situation actuelle

```
• Application web monolithique
• Un seul firewall en entrée
• Tous les utilisateurs = administrateurs
• Développeurs déploient directement en prod
• Authentification custom (algo maison)
• 150 endpoints REST
• SSH sur port 22, root login activé
• Pas de MFA
```

### Question

**Quels principes sont violés ? Quelles corrections ?**

---

## Slide 40 : Corrections proposées

| Principe violé | Problème | Solution |
|----------------|----------|----------|
| **Defense in Depth** | 1 seul firewall | + WAF + IDS/IPS + Segmentation |
| **Least Privilege** | Tous admin | RBAC + Comptes standards |
| **Separation of Duties** | Dev = Deploy | Pipeline CI/CD avec approbations |
| **Secure by Design** | Auth custom | OAuth 2.0 + MFA |
| **KISS** | 150 endpoints | Réduire aux nécessaires |
| **Not Obscurity** | Port 22 seul | Clés SSH + Firewall whitelist |

---

## Slide 41 : Architecture cible

```
┌─────────────────────────────────────────┐
│ UTILISATEURS (MFA obligatoire)          │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ FIREWALL + WAF + Anti-DDoS              │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ API GATEWAY (OAuth 2.0, Rate Limiting)  │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ MICROSERVICES (RBAC, Least Privilege)   │
└──────────────┬──────────────────────────┘
               ↓
┌─────────────────────────────────────────┐
│ DATABASE (Chiffrement, Audit)           │
└─────────────────────────────────────────┘

      + SIEM + SOC + Monitoring 24/7
```

---

## Slide 42 : Pipeline CI/CD sécurisé

```
CODE COMMIT
    ↓
┌─────────────────────────┐
│ SAST (Analyse statique) │ ← Automatique
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ SCA (Dépendances)       │ ← Automatique
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ CODE REVIEW             │ ← Lead Dev (SoD)
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ DAST (Tests dynamiques) │ ← Automatique
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ APPROBATION SÉCURITÉ    │ ← RSSI (SoD)
└───────────┬─────────────┘
            ↓
┌─────────────────────────┐
│ DÉPLOIEMENT PRODUCTION  │ ← DevOps (SoD)
└─────────────────────────┘
```

---

## PARTIE 8 : SYNTHÈSE

---

## Slide 43 : Récapitulatif des 6 principes

| Principe | Objectif principal | Application clé |
|----------|-------------------|-----------------|
| **Defense in Depth** | Résilience | Multiples couches de sécurité |
| **Least Privilege** | Limitation dégâts | Accès minimum nécessaire |
| **Separation of Duties** | Prévention fraude | Contrôle divisé entre plusieurs |
| **Secure by Design** | Réduction coûts | Sécurité dès la conception |
| **KISS** | Réduction complexité | Simplicité = moins de bugs |
| **NOT Obscurity** | Vraie sécurité | Standards publics + secrets changeables |

---

## Slide 44 : Interdépendances des principes

```
        ┌─────────────────────┐
        │  SECURE BY DESIGN   │ ← Fondation
        └──────────┬──────────┘
                   │
   ┌───────────────┼───────────────┐
   ↓               ↓               ↓
┌────────┐    ┌────────┐    ┌──────────────┐
│Defense │    │  KISS  │    │Least Privilege│
│in Depth│    │        │    │               │
└────────┘    └────────┘    └──────────────┘
   │               │               │
   └───────────────┼───────────────┘
                   ↓
        ┌──────────────────────┐
        │ Separation of Duties │
        └──────────────────────┘
                   ↓
        ┌──────────────────────┐
        │  Architecture Sûre   │ ← Résultat
        └──────────────────────┘
```

**Les principes se renforcent mutuellement**

---

## Slide 45 : KPIs de sécurité

### Indicateurs à surveiller

| KPI | Objectif |
|-----|----------|
| **Nombre de couches défense** | ≥ 3 pour actifs critiques |
| **Taux comptes à privilèges** | < 5% |
| **Processus avec SoD** | 100% processus critiques |
| **Vulnérabilités pré-prod** | > 80% détectées avant prod |
| **Complexité code moyenne** | < 10 par fonction |
| **Incidents sécurité** | Tendance baisse |
| **Time to remediation** | < 72h (vulnérabilités HIGH) |

---

## Slide 46 : Erreurs courantes à éviter

### Top 5 des erreurs

1. **Appliquer un seul principe**
   → Defense in Depth sans Least Privilege = inefficace

2. **Sur-complexifier au nom de la sécurité**
   → Violation du KISS

3. **Ajouter la sécurité après coup**
   → Coût 1000x plus élevé

4. **Compter sur l'obscurité seule**
   → Fausse sécurité

5. **Oublier l'humain**
   → Formation et culture essentielles

---

## Slide 47 : Checklist de conformité

```markdown
Architecture sécurisée - Checklist

□ Defense in Depth : Au moins 3 couches
□ Least Privilege : RBAC implémenté
□ Separation of Duties : Workflow approbations
□ Secure by Design : Threat model réalisé
□ KISS : Complexité minimale
□ Standards publics : Pas de crypto maison
□ MFA activé pour comptes privilégiés
□ Chiffrement TLS 1.3 + Data at rest
□ SIEM + Monitoring 24/7
□ Plan de réponse aux incidents
□ Formation sécurité annuelle
□ Audits réguliers
```

---

## Slide 48 : Évolution des menaces 2024-2026

### Tendances

- **Supply chain attacks** ↗ +45%
- **Ransomware-as-a-Service** ↗ +38%
- **IA pour attaques** ↗ +52%
- **Zero-day exploits** ↗ +28%
- **Attaques cloud/containers** ↗ +63%

### Adaptation nécessaire

- Defense in Depth → Inclure la supply chain
- Least Privilege → Workloads cloud
- Secure by Design → DevSecOps obligatoire
- KISS → Architecture cloud-native

---

## Slide 49 : Ressources et outils

### Standards et frameworks
- **OWASP** - Top 10, SAMM, ASVS
- **NIST** - Cybersecurity Framework
- **ISO 27001/27002** - Sécurité de l'information
- **ANSSI** - Guides et recommandations

### Outils open source
- **SAST** : SonarQube, Semgrep
- **DAST** : OWASP ZAP, Burp Suite
- **SCA** : Snyk, Dependabot
- **Container** : Trivy, Clair
- **IaC** : Checkov, tfsec

---

## Slide 50 : Conclusion

### Messages clés

1. **La sécurité est un processus, pas un produit**
   → Amélioration continue

2. **Pas de sécurité absolue**
   → Gérer le risque résiduel

3. **L'humain reste le maillon faible**
   → Culture de sécurité essentielle

4. **Simplicité et profondeur**
   → KISS + Defense in Depth

5. **Intégrer dès le début**
   → Secure by Design = ROI maximal

---

## Slide 51 : Derniers conseils

### 5 principes d'action

1. **Commencer petit**
   → Appliquer un principe à la fois

2. **Mesurer et améliorer**
   → KPIs + revue régulière

3. **Former et sensibiliser**
   → Toute l'organisation

4. **Automatiser**
   → SAST/DAST dans CI/CD

5. **Documenter**
   → Capitaliser sur l'expérience

### Citation finale

> "The best time to think about security was yesterday. The next best time is now."

---

## Slide 52 : Questions / Réponses

### Merci de votre attention !

**Contact et ressources :**
- Documentation complète disponible
- Templates et checklists fournis
- Support et formation continue

**Questions ?**

---

## Slide 53 : Annexe - Templates fournis

### Documents disponibles

1. **Threat Model Template**
   → Méthodologie STRIDE

2. **Security Review Checklist**
   → Audit avant mise en production

3. **Architecture Decision Record**
   → Documentation des choix de sécurité

4. **Incident Response Plan**
   → Procédure en cas d'incident

5. **RBAC Matrix Template**
   → Gestion des rôles et permissions

---

## Notes pour le présentateur

### Durée des sections

- Introduction : 5 min
- Defense in Depth : 8 min
- Least Privilege : 7 min
- Separation of Duties : 7 min
- Secure by Design : 8 min
- KISS : 6 min
- Security by Obscurity : 6 min
- Mise en pratique : 8 min
- Conclusion : 5 min

**Total : 60 minutes**

### Conseils de présentation

1. **Interactivité** : Poser des questions à l'audience
2. **Exemples concrets** : Adapter aux contextes de l'entreprise
3. **Démonstrations** : Montrer des outils en live si possible
4. **Pauses** : Prévoir une pause à mi-parcours
5. **Support visuel** : Utiliser des schémas et diagrammes

### Points d'attention

- Insister sur les **interdépendances** entre principes
- Montrer le **ROI** de Secure by Design
- Démystifier Security by Obscurity (beaucoup de croyances)
- Cas pratiques = meilleur moment pour l'engagement

---

**FIN DE LA PRÉSENTATION**

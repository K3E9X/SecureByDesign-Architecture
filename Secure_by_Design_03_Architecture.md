# PHASE 3 : ARCHITECTURE SÉCURISÉE

[← Phase 2 : Threat Modeling](Secure_by_Design_02_Threat_Modeling.md) | [Retour à l'index](Secure_by_Design_00_Index.md) | [Phase 4 : Développement →](Secure_by_Design_04_Developpement.md)

---

## Table des matières

1. [Vue d'ensemble](#vue-densemble)
2. [Principes d'architecture sécurisée](#principes)
3. [Zero Trust Architecture](#zero-trust)
4. [Patterns de sécurité](#patterns)
5. [Architecture par couches](#couches)
6. [Exemples d'architectures](#exemples)
7. [Choix technologiques](#technologies)
8. [Diagrammes détaillés](#diagrammes)

---

## Vue d'ensemble {#vue-densemble}

L'**Architecture Sécurisée** consiste à concevoir la structure technique du système en intégrant la sécurité comme un élément fondamental, en s'appuyant sur les menaces identifiées lors du Threat Modeling.

### Objectifs de cette phase

1. **Traduire** les exigences de sécurité en design technique
2. **Appliquer** les patterns de sécurité éprouvés
3. **Concevoir** la segmentation et l'isolation des composants
4. **Définir** les flux de données sécurisés
5. **Sélectionner** les technologies appropriées

### Livrables attendus

- Document d'architecture de sécurité
- Diagrammes d'architecture (C4, UML, Mermaid)
- Matrice de sécurisation par composant
- Spécifications techniques de sécurité
- Decision records (ADR - Architecture Decision Records)

---

## Principes d'architecture sécurisée {#principes}

### 1. Defense in Depth (Défense en profondeur)

**Concept :** Plusieurs couches de sécurité indépendantes

```mermaid
graph TB
    subgraph Layer1["Couche 1: Périmètre"]
        FW[Firewall]
        DDoS[Anti-DDoS]
    end

    subgraph Layer2["Couche 2: Réseau"]
        WAF[WAF]
        IDS[IDS/IPS]
        Seg[Segmentation]
    end

    subgraph Layer3["Couche 3: Application"]
        AuthN[Authentification]
        AuthZ[Autorisation]
        Valid[Validation inputs]
    end

    subgraph Layer4["Couche 4: Données"]
        Encrypt[Chiffrement]
        Mask[Masquage]
        Audit[Audit logs]
    end

    Internet -->|Attack| Layer1
    Layer1 --> Layer2
    Layer2 --> Layer3
    Layer3 --> Layer4

    style Layer1 fill:#ffcccc
    style Layer2 fill:#ffffcc
    style Layer3 fill:#ccffcc
    style Layer4 fill:#ccccff
```

**Application :** Si une couche est contournée, les autres continuent à protéger.

### 2. Least Privilege (Moindre privilège)

**Concept :** Accès minimum nécessaire pour fonctionner

```yaml
# Exemple Kubernetes RBAC
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  namespace: production
  name: payment-service-role
rules:
  # Uniquement ce qui est nécessaire
  - apiGroups: [""]
    resources: ["secrets"]
    resourceNames: ["stripe-api-key"]  # Secret spécifique uniquement
    verbs: ["get"]

  - apiGroups: [""]
    resources: ["configmaps"]
    resourceNames: ["payment-config"]
    verbs: ["get"]

  # PAS de droits admin, PAS d'accès autres secrets
```

### 3. Fail Secure (Échec sécurisé)

**Concept :** En cas d'erreur, refuser l'accès par défaut

```python
# Mauvais exemple - Fail Open
def check_access(user, resource):
    try:
        return permission_service.verify(user, resource)
    except Exception:
        # DANGER : En cas d'erreur, on autorise !
        return True

# Bon exemple - Fail Secure
def check_access(user, resource):
    try:
        return permission_service.verify(user, resource)
    except Exception as e:
        logger.error(f"Permission check failed: {e}")
        # En cas d'erreur, on REFUSE
        return False
```

### 4. Complete Mediation (Médiation complète)

**Concept :** Vérifier les permissions à CHAQUE accès

```javascript
// Mauvais - Vérification uniquement au login
app.get('/api/account/:id', async (req, res) => {
  // Pas de vérification, on suppose que l'utilisateur est autorisé
  const account = await db.getAccount(req.params.id);
  res.json(account);
});

// Bon - Vérification à chaque requête
app.get('/api/account/:id',
  authenticateJWT,  // Vérifier token
  async (req, res) => {
    const accountId = req.params.id;

    // Vérifier que l'utilisateur peut accéder à CE compte
    if (!canAccessAccount(req.user.id, accountId)) {
      return res.status(403).json({ error: 'Forbidden' });
    }

    const account = await db.getAccount(accountId);
    res.json(account);
  }
);
```

### 5. Separation of Duties (Séparation des responsabilités)

**Concept :** Diviser les responsabilités critiques

```mermaid
graph LR
    Dev[Développeur] -->|Écrit code| Code[Code]
    Code -->|PR| Review[Code Review]
    Lead[Lead Dev] -->|Approuve| Review
    Review -->|Merge| Main[Main Branch]
    Main -->|Trigger| CI[CI/CD]
    DevOps[DevOps] -->|Approuve deploy| Prod[Production]

    Dev -.X.->|Ne peut PAS| Prod
    Lead -.X.->|Ne peut PAS| Prod
    DevOps -.X.->|Ne peut PAS| Code

    style Dev fill:#ffd700
    style Lead fill:#87ceeb
    style DevOps fill:#98fb98
```

### 6. Economy of Mechanism (Simplicité)

**Concept :** Plus c'est simple, plus c'est sécurisé

```python
# Complexe = Vulnérable
def custom_crypto_hash(password, salt, iterations, algorithm, pepper, ...):
    # 200 lignes de cryptographie maison
    # Probablement cassable
    pass

# Simple = Sûr
from werkzeug.security import generate_password_hash

hashed = generate_password_hash(password)  # bcrypt, audité, maintenu
```

---

## Zero Trust Architecture {#zero-trust}

### Concept

**Zero Trust :** "Never trust, always verify"

**Principes clés :**
1. ❌ Pas de "réseau de confiance"
2. ✅ Vérifier **chaque** accès
3. ✅ Assumer que le réseau est compromis
4. ✅ Micro-segmentation
5. ✅ Least privilege partout

### Comparaison : Modèle traditionnel vs Zero Trust

```mermaid
graph TB
    subgraph Traditional["Modèle Traditionnel (Château-Douve)"]
        Internet1[Internet] -->|Firewall| DMZ1[DMZ]
        DMZ1 --> Internal1[Réseau Interne]
        Internal1 --> Trust1["Zone de confiance<br/>Tout le monde se fait confiance"]

        style Trust1 fill:#ffcccc
    end

    subgraph ZeroTrust["Modèle Zero Trust"]
        Internet2[Internet] --> Gateway2[Gateway]
        Gateway2 --> Auth2[Authentification]
        Auth2 --> Policy2[Policy Engine]
        Policy2 --> Micro1[Microservice 1]
        Policy2 --> Micro2[Microservice 2]
        Policy2 --> Data2[Data]

        Micro1 -.mTLS.-> Micro2
        Micro2 -.mTLS.-> Data2

        style Policy2 fill:#90EE90
    end
```

### Architecture Zero Trust détaillée

```mermaid
graph TB
    User[👤 Utilisateur<br/>Device] -->|1. Request| PEP[Policy Enforcement Point<br/>API Gateway]

    PEP -->|2. Auth Request| IdP[Identity Provider<br/>Okta / Azure AD]
    IdP -->|3. JWT Token| PEP

    PEP -->|4. Authorization Request| PDP[Policy Decision Point<br/>OPA / Cedar]

    PDP -->|5. Query Context| PIP[Policy Information Point]
    PIP -->|6. User attributes<br/>Device posture<br/>Risk score| PDP

    PDP -->|7. Decision<br/>ALLOW/DENY| PEP

    PEP -->|8. Access| App[Application]

    App -->|9. mTLS| Service[Microservice]
    Service -->|10. mTLS + AuthZ| DB[(Database)]

    subgraph Monitoring["Monitoring Continu"]
        SIEM[SIEM]
        Behavior[Behavioral Analytics]
    end

    PEP -.Log.-> SIEM
    App -.Log.-> SIEM
    SIEM --> Behavior
    Behavior -.Feed Risk Score.-> PIP

    style PEP fill:#ff6b6b
    style PDP fill:#4ecdc4
    style PIP fill:#95e1d3
    style IdP fill:#ffd93d
```

**Composants Zero Trust :**

| Composant | Rôle | Technologies |
|-----------|------|--------------|
| **PEP** (Policy Enforcement Point) | Applique les décisions | API Gateway (Kong, Envoy) |
| **PDP** (Policy Decision Point) | Décide Autoriser/Refuser | OPA, AWS Cedar, Google Zanzibar |
| **PIP** (Policy Information Point) | Fournit contexte | CMDB, SIEM, Risk scoring |
| **IdP** (Identity Provider) | Authentifie | Okta, Azure AD, Keycloak |

### Implémentation Zero Trust avec OPA (Open Policy Agent)

```rego
# policy.rego - Politique Zero Trust

package bankapp.authorization

import future.keywords.if
import future.keywords.in

# Par défaut, tout est REFUSÉ
default allow = false

# Règle 1 : Utilisateur doit être authentifié
allow if {
    input.user.authenticated == true
    input.user.mfa_verified == true
}

# Règle 2 : Virement > 1000€ nécessite Strong Customer Authentication
allow if {
    input.action == "transfer"
    input.amount <= 1000
    valid_user_context
}

allow if {
    input.action == "transfer"
    input.amount > 1000
    valid_user_context
    input.user.sca_verified == true  # SCA requis
    input.device.trusted == true
}

# Règle 3 : Accès admin uniquement depuis VPN + IP whitelistée
allow if {
    input.user.role == "admin"
    input.network.vpn == true
    input.source_ip in data.admin_ips
    input.time.hour >= 8
    input.time.hour <= 18  # Heures ouvrables uniquement
}

# Règle 4 : Détection d'anomalie géographique
allow if {
    not suspicious_location
    valid_user_context
}

# Fonctions helpers
valid_user_context if {
    input.user.authenticated == true
    input.user.account_status == "active"
    not input.user.flagged_for_fraud
}

suspicious_location if {
    # Changement de pays en moins de 1 heure = suspect
    last_login_country := data.user_history[input.user.id].last_country
    current_country := input.geo.country

    last_login_country != current_country
    time_since_last_login_minutes < 60
}
```

**Utilisation dans l'API Gateway (Kong + OPA plugin) :**

```yaml
# kong.yaml
services:
  - name: payment-service
    url: http://payment-service:8080
    routes:
      - name: transfer
        paths:
          - /api/v1/transfer
    plugins:
      - name: opa
        config:
          policy_uri: http://opa:8181/v1/data/bankapp/authorization/allow
          include_body: true
          include_headers: true
```

**Requête exemple :**

```json
POST /api/v1/transfer

Headers:
  Authorization: Bearer eyJhbGc...
  X-Device-ID: abc123

Body:
{
  "from": "FR76...",
  "to": "FR89...",
  "amount": 5000,
  "currency": "EUR"
}

→ Kong envoie à OPA :
{
  "input": {
    "user": {
      "id": "user-123",
      "authenticated": true,
      "mfa_verified": true,
      "sca_verified": false,  ← Problème !
      "role": "customer"
    },
    "action": "transfer",
    "amount": 5000,  ← > 1000€
    "device": {
      "id": "abc123",
      "trusted": true
    },
    "source_ip": "203.0.113.42",
    "geo": {
      "country": "FR"
    }
  }
}

← OPA répond :
{
  "result": false,  ← REFUSÉ
  "reason": "SCA required for transfers > 1000€"
}

→ Kong retourne 403 Forbidden avec message approprié
```

---

## Patterns de sécurité {#patterns}

### 1. API Gateway Pattern

**Problème :** Multiples microservices, chacun doit gérer auth, rate limiting, logs...

**Solution :** Centraliser les préoccupations transverses

```mermaid
graph LR
    Client[Client] --> Gateway[API Gateway]

    Gateway --> Auth[Auth]
    Gateway --> RateLimit[Rate Limiting]
    Gateway --> Log[Logging]
    Gateway --> Transform[Transformation]

    Gateway --> MS1[Microservice 1]
    Gateway --> MS2[Microservice 2]
    Gateway --> MS3[Microservice 3]

    style Gateway fill:#4ecdc4
```

**Bénéfices :**
- ✅ Single point of entry
- ✅ Centralisation sécurité
- ✅ Simplification microservices
- ✅ Rate limiting global

**Inconvénients :**
- ⚠️ Single point of failure (mitigé par HA)
- ⚠️ Peut devenir bottleneck (mitigé par scaling)

### 2. Circuit Breaker Pattern

**Problème :** Service dépendant crashe ou est lent → cascade failure

**Solution :** Couper automatiquement si trop d'échecs

```python
from circuitbreaker import circuit

@circuit(failure_threshold=5, recovery_timeout=60)
def call_payment_gateway(transaction):
    """
    Circuit ouvert si 5 échecs consécutifs
    Retente après 60 secondes
    """
    response = requests.post(
        'https://payment-gateway.com/api/charge',
        json=transaction,
        timeout=5
    )
    response.raise_for_status()
    return response.json()

# Utilisation
try:
    result = call_payment_gateway(tx_data)
except CircuitBreakerError:
    # Circuit ouvert, service indisponible
    logger.warning("Payment gateway circuit open")
    return {"error": "Service temporarily unavailable", "retry_after": 60}
```

**États du circuit :**

```mermaid
stateDiagram-v2
    [*] --> Closed
    Closed --> Open : Threshold atteint<br/>(5 échecs)
    Open --> HalfOpen : Timeout expiré<br/>(60s)
    HalfOpen --> Closed : Succès
    HalfOpen --> Open : Échec

    note right of Closed
        Trafic normal
        Compte les échecs
    end note

    note right of Open
        Bloque les requêtes
        Fail fast
    end note

    note right of HalfOpen
        Teste 1 requête
        Décide réouverture
    end note
```

### 3. Secrets Management Pattern

**Problème :** Secrets (API keys, passwords) dans le code ou config

**Solution :** Centraliser dans un vault

```mermaid
graph TB
    App[Application] -->|1. Request secret| Vault[HashiCorp Vault]

    Vault -->|2. Authenticate| Auth[Auth Backend<br/>Kubernetes / AWS IAM]
    Auth -->|3. Token| Vault

    Vault -->|4. Check policy| Policy[Policy Engine]
    Policy -->|5. Authorized| Vault

    Vault -->|6. Encrypted secret| App

    Vault --> Audit[Audit Log]

    style Vault fill:#4ecdc4
    style Policy fill:#ff6b6b
```

**Exemple HashiCorp Vault :**

```bash
# 1. Activer secrets engine
vault secrets enable -path=bankapp kv-v2

# 2. Stocker secret
vault kv put bankapp/stripe \
  api_key="sk_live_..." \
  webhook_secret="whsec_..."

# 3. Créer policy
vault policy write payment-service - <<EOF
path "bankapp/data/stripe" {
  capabilities = ["read"]
}
EOF

# 4. Lier policy au service (via Kubernetes service account)
vault write auth/kubernetes/role/payment-service \
  bound_service_account_names=payment-service \
  bound_service_account_namespaces=production \
  policies=payment-service \
  ttl=1h
```

**Dans l'application :**

```python
import hvac

# Connexion à Vault via Kubernetes auth
client = hvac.Client(url='http://vault:8200')

# Authentification automatique via service account
with open('/var/run/secrets/kubernetes.io/serviceaccount/token') as f:
    jwt = f.read()

client.auth.kubernetes.login(
    role='payment-service',
    jwt=jwt
)

# Récupération du secret
secret = client.secrets.kv.v2.read_secret_version(
    path='stripe',
    mount_point='bankapp'
)

STRIPE_API_KEY = secret['data']['data']['api_key']
# Pas de hardcoding, pas de variable d'environnement en clair
```

### 4. Strangler Fig Pattern (Migration sécurisée)

**Problème :** Migrer une app legacy monolithique vers microservices

**Solution :** Rediriger progressivement le trafic

```mermaid
graph TB
    Client[Client] --> Proxy[Reverse Proxy<br/>Intelligent Routing]

    Proxy -->|New endpoints| NewMS[Nouveaux<br/>Microservices<br/>Sécurisés]
    Proxy -->|Legacy endpoints| Legacy[Application<br/>Legacy<br/>Monolithique]

    NewMS --> NewDB[(Nouvelle DB<br/>Chiffrée)]
    Legacy --> LegacyDB[(Legacy DB)]

    NewMS -.Sync data.-> LegacyDB

    style NewMS fill:#90EE90
    style Legacy fill:#ffcccc
```

**Configuration Nginx :**

```nginx
# strangler.conf

upstream legacy_app {
    server legacy:8080;
}

upstream new_microservices {
    server api-gateway:8080;
}

server {
    listen 443 ssl http2;
    server_name bankapp.com;

    # Nouveaux endpoints sécurisés → Microservices
    location /api/v2/ {
        proxy_pass http://new_microservices;

        # Headers sécurité
        add_header Strict-Transport-Security "max-age=31536000" always;
        add_header X-Content-Type-Options "nosniff" always;
        add_header X-Frame-Options "DENY" always;
    }

    # Anciens endpoints → Legacy (temporaire)
    location /api/v1/ {
        proxy_pass http://legacy_app;

        # Logs pour tracking migration
        access_log /var/log/nginx/legacy_usage.log combined;
    }

    # Feature flag : redirection progressive
    location /api/v1/accounts {
        # Si header X-Beta: true → nouveau service
        if ($http_x_beta = "true") {
            proxy_pass http://new_microservices/api/v2/accounts;
        }

        # Sinon → legacy
        proxy_pass http://legacy_app;
    }
}
```

### 5. Backends for Frontends (BFF) Pattern

**Problème :** API unique pour mobile + web + IoT → over-fetching, complexité

**Solution :** Backend dédié par type de client

```mermaid
graph TB
    Mobile[📱 Mobile App] --> BFFM[BFF Mobile<br/>API optimisée mobile]
    Web[🌐 Web App] --> BFFW[BFF Web<br/>API complète]
    IoT[🔌 IoT Device] --> BFFI[BFF IoT<br/>API minimale]

    BFFM --> MS1[Microservice 1]
    BFFM --> MS2[Microservice 2]
    BFFW --> MS1
    BFFW --> MS2
    BFFW --> MS3[Microservice 3]
    BFFI --> MS1

    style BFFM fill:#ffd93d
    style BFFW fill:#4ecdc4
    style BFFI fill:#95e1d3
```

**Bénéfices sécurité :**
- ✅ Surface d'attaque réduite par client
- ✅ Policies différentes (mobile = MFA, IoT = cert client)
- ✅ Rate limiting adapté par type

---

## Architecture par couches {#couches}

### Architecture complète BankApp

```mermaid
graph TB
    subgraph Presentation["COUCHE PRÉSENTATION"]
        iOS[iOS App]
        Android[Android App]
        Web[Web Browser]
    end

    subgraph EdgeLayer["EDGE LAYER (CDN + DDoS Protection)"]
        CF[Cloudflare]
    end

    subgraph DMZ["DMZ"]
        LB[Load Balancer<br/>NGINX]
        WAF[WAF<br/>ModSecurity]
    end

    subgraph APILayer["API LAYER"]
        Gateway[API Gateway<br/>Kong]
        BFFMobile[BFF Mobile]
        BFFWeb[BFF Web]
    end

    subgraph ServiceLayer["SERVICE LAYER (mTLS)"]
        Auth[Auth Service<br/>OAuth 2.0]
        Account[Account Service]
        Payment[Payment Service]
        Notification[Notification Service]
        Fraud[Fraud Detection]
    end

    subgraph DataLayer["DATA LAYER"]
        UserDB[(User DB<br/>PostgreSQL<br/>Encrypted)]
        AccountDB[(Account DB<br/>PostgreSQL<br/>Encrypted)]
        Cache[(Redis<br/>TLS)]
        Vault[(HashiCorp Vault<br/>Secrets)]
    end

    subgraph ExternalServices["SERVICES EXTERNES"]
        Stripe[Stripe<br/>Payment Gateway]
        Twilio[Twilio<br/>SMS/Email]
        CoreBanking[Core Banking<br/>Mainframe]
    end

    subgraph Monitoring["MONITORING & SECURITY"]
        SIEM[SIEM<br/>Splunk]
        Metrics[Metrics<br/>Prometheus]
        Logs[Logs<br/>ELK]
    end

    iOS --> CF
    Android --> CF
    Web --> CF

    CF --> LB
    LB --> WAF
    WAF --> Gateway

    Gateway --> BFFMobile
    Gateway --> BFFWeb

    BFFMobile --> Auth
    BFFMobile --> Account
    BFFWeb --> Auth
    BFFWeb --> Account
    BFFWeb --> Payment

    Auth --> UserDB
    Auth --> Cache
    Account --> AccountDB
    Payment --> Vault
    Payment --> Stripe
    Payment --> CoreBanking
    Notification --> Twilio

    Payment --> Fraud

    Auth -.Logs.-> SIEM
    Gateway -.Logs.-> SIEM
    Payment -.Logs.-> SIEM

    Account -.Metrics.-> Metrics
    Payment -.Metrics.-> Metrics

    style EdgeLayer fill:#ffcccc
    style DMZ fill:#ffffcc
    style APILayer fill:#ccffcc
    style ServiceLayer fill:#ccffff
    style DataLayer fill:#ffccff
    style Monitoring fill:#e0e0e0
```

### Matrice de sécurisation par couche

| Couche | Contrôles de sécurité | Technologies |
|--------|----------------------|--------------|
| **Edge** | • Anti-DDoS (138 Tbps)<br>• WAF managed<br>• Rate limiting global<br>• Bot mitigation | Cloudflare Enterprise |
| **DMZ** | • WAF (OWASP CRS)<br>• TLS termination<br>• IP whitelisting<br>• GeoIP blocking | NGINX + ModSecurity |
| **API Gateway** | • JWT validation<br>• Rate limiting per user<br>• Request/response logging<br>• API key management | Kong + OPA |
| **Services** | • mTLS entre services<br>• RBAC<br>• Input validation<br>• Circuit breakers | Service Mesh (Istio) |
| **Data** | • Encryption at rest (AES-256)<br>• Encryption in transit (TLS 1.3)<br>• Access control (RBAC)<br>• Audit logging | PostgreSQL + TDE<br>Redis TLS |
| **Monitoring** | • SIEM<br>• Behavioral analytics<br>• Alerting<br>• Incident response | Splunk + PagerDuty |

---

## Exemples d'architectures {#exemples}

### Architecture Microservices avec Service Mesh

```mermaid
graph TB
    subgraph Outside["External"]
        Client[Client]
    end

    subgraph IngressLayer["Ingress"]
        Ingress[Istio Ingress Gateway]
    end

    subgraph ServiceMesh["Service Mesh (Istio)"]
        subgraph NS1["Namespace: auth"]
            Auth[Auth Service]
            AuthProxy[Envoy Sidecar]
            Auth -.-> AuthProxy
        end

        subgraph NS2["Namespace: payments"]
            Payment[Payment Service]
            PaymentProxy[Envoy Sidecar]
            Payment -.-> PaymentProxy
        end

        subgraph NS3["Namespace: accounts"]
            Account[Account Service]
            AccountProxy[Envoy Sidecar]
            Account -.-> AccountProxy
        end
    end

    subgraph ControlPlane["Istio Control Plane"]
        Pilot[Pilot<br/>Traffic Management]
        Citadel[Citadel<br/>Certificate Management]
        Galley[Galley<br/>Configuration]
    end

    Client -->|HTTPS| Ingress
    Ingress -->|mTLS| AuthProxy
    AuthProxy <-->|mTLS| PaymentProxy
    AuthProxy <-->|mTLS| AccountProxy
    PaymentProxy <-->|mTLS| AccountProxy

    Pilot -.Config.-> AuthProxy
    Pilot -.Config.-> PaymentProxy
    Pilot -.Config.-> AccountProxy

    Citadel -.Certs.-> AuthProxy
    Citadel -.Certs.-> PaymentProxy
    Citadel -.Certs.-> AccountProxy

    style ServiceMesh fill:#e3f2fd
    style ControlPlane fill:#fff3e0
```

**Configuration Istio - mTLS strict :**

```yaml
# peer-authentication.yaml
apiVersion: security.istio.io/v1beta1
kind: PeerAuthentication
metadata:
  name: default
  namespace: production
spec:
  mtls:
    mode: STRICT  # mTLS obligatoire entre tous les services

---
# authorization-policy.yaml
apiVersion: security.istio.io/v1beta1
kind: AuthorizationPolicy
metadata:
  name: payment-authz
  namespace: production
spec:
  selector:
    matchLabels:
      app: payment-service

  action: ALLOW

  rules:
    # Seul account-service peut appeler payment-service
    - from:
        - source:
            principals: ["cluster.local/ns/production/sa/account-service"]
      to:
        - operation:
            methods: ["POST"]
            paths: ["/internal/api/v1/process-payment"]
```

### Architecture Serverless Sécurisée (AWS)

```mermaid
graph TB
    Client[Client] -->|HTTPS| CloudFront[CloudFront<br/>CDN + WAF]
    CloudFront --> APIGateway[API Gateway<br/>+ Authorizer]

    APIGateway -->|Invoke| Lambda1[Lambda<br/>Auth Function]
    APIGateway -->|Invoke| Lambda2[Lambda<br/>Account Function]
    APIGateway -->|Invoke| Lambda3[Lambda<br/>Payment Function]

    Lambda1 --> Cognito[Amazon Cognito<br/>User Pool]
    Lambda2 --> DDB[(DynamoDB<br/>Encrypted)]
    Lambda3 --> SecretsManager[Secrets Manager]
    Lambda3 --> SQS[SQS Queue<br/>Encrypted]

    SQS --> Lambda4[Lambda<br/>Async Processor]

    Lambda1 -.Logs.-> CloudWatch[CloudWatch Logs]
    Lambda2 -.Logs.-> CloudWatch
    Lambda3 -.Logs.-> CloudWatch

    CloudWatch --> SNS[SNS<br/>Alerts]

    subgraph VPC["VPC (Isolated)"]
        Lambda3
        DDB
    end

    style CloudFront fill:#ff9900
    style APIGateway fill:#ff9900
    style VPC fill:#232f3e,color:#fff
```

**Sécurisation Lambda :**

```yaml
# serverless.yml
service: bankapp

provider:
  name: aws
  runtime: python3.11
  region: eu-west-1

  # Least privilege par fonction
  iam:
    role:
      statements:
        - Effect: Allow
          Action:
            - dynamodb:GetItem
            - dynamodb:PutItem
          Resource: !GetAtt AccountTable.Arn

        - Effect: Allow
          Action:
            - secretsmanager:GetSecretValue
          Resource: arn:aws:secretsmanager:eu-west-1:123456789:secret:stripe-api-key-*

  # Encryption
  environment:
    STAGE: ${self:provider.stage}
    # Secrets via Secrets Manager (pas en clair ici)

  # VPC pour isolation
  vpc:
    securityGroupIds:
      - sg-xxxxx
    subnetIds:
      - subnet-xxxxx
      - subnet-yyyyy

functions:
  processPayment:
    handler: handlers/payment.process
    timeout: 30
    reservedConcurrency: 100  # Limit DoS

    # Variables chiffrées
    environment:
      STRIPE_SECRET_ARN: arn:aws:secretsmanager:...

    events:
      - http:
          path: /payment
          method: post
          authorizer:
            name: authFunction
            resultTtlInSeconds: 300

          # Validation des inputs
          request:
            schemas:
              application/json: ${file(schemas/payment-request.json)}

resources:
  Resources:
    # Table DynamoDB chiffrée
    AccountTable:
      Type: AWS::DynamoDB::Table
      Properties:
        TableName: accounts-${self:provider.stage}
        SSESpecification:
          SSEEnabled: true
          SSEType: KMS
          KMSMasterKeyId: alias/aws/dynamodb

        PointInTimeRecoverySpecification:
          PointInTimeRecoveryEnabled: true
```

---

## Choix technologiques {#technologies}

### Matrice de décision : API Gateway

| Critère | Kong | AWS API Gateway | Nginx + Lua | Envoy |
|---------|------|----------------|-------------|-------|
| **Open Source** | ✅ (+ Enterprise) | ❌ (Managed) | ✅ | ✅ |
| **Rate Limiting** | ✅ Excellent | ✅ Bon | ⚠️ Custom | ✅ Bon |
| **Plugin Ecosystem** | ✅ Large | ⚠️ Limité | ⚠️ Custom | ✅ Filters |
| **OAuth 2.0** | ✅ Native | ✅ Cognito | ⚠️ Custom | ⚠️ Ext Auth |
| **Monitoring** | ✅ Prometheus | ✅ CloudWatch | ⚠️ Custom | ✅ Prometheus |
| **Performance** | ✅ Excellent | ✅ Auto-scale | ✅ Excellent | ✅ Excellent |
| **Learning Curve** | ⚠️ Moyen | ✅ Facile | ❌ Difficile | ⚠️ Moyen |
| **Cost** | 💰💰 (Enterprise) | 💰 Pay-per-use | 💰 Infra only | 💰 Infra only |

**Recommandation pour BankApp :** Kong Enterprise
- Fonctionnalités sécurité riches
- Support PCI-DSS
- Audit trail complet
- Support professionnel

---

[← Phase 2 : Threat Modeling](Secure_by_Design_02_Threat_Modeling.md) | [Phase 4 : Développement Sécurisé →](Secure_by_Design_04_Developpement.md)

**Version :** 1.0
**Date :** 2026-01-05

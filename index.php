<?php
session_start();

/* settings bdd */
$host   = "sql311.infinityfree.com";     
$dbname = "if0_40331423_bdd1";           
$dbuser = "if0_40331423";           
$dbpass = "5hmar1ooZ4LR";               

try {
    $pdo = new PDO(
        "mysql:host=$host;dbname=$dbname;charset=utf8mb4",
        $dbuser,
        $dbpass,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException $e) {
    die("Erreur de connexion : " . htmlspecialchars($e->getMessage()));
}

/* var */
$currentUser = null;
$isAdmin     = false;
$message     = "";

/* déploiement des fonctions */

function firstAdminExists(PDO $pdo): bool {
    $stmt = $pdo->query("SELECT COUNT(*) FROM utilisateur WHERE role = 'admin'");
    return (bool)$stmt->fetchColumn();
}

function getUserByNom(PDO $pdo, string $nom) {
    $sql = "SELECT * FROM utilisateur WHERE nom = :n LIMIT 1";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':n' => $nom]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

function getCurrentUser(PDO $pdo) {
    if (!isset($_SESSION['user_id'])) {
        return null;
    }
    $sql = "SELECT * FROM utilisateur WHERE id_utilisateur = :id LIMIT 1";
    $stmt = $pdo->prepare($sql);
    $stmt->execute([':id' => $_SESSION['user_id']]);
    return $stmt->fetch(PDO::FETCH_ASSOC);
}

/* déco */

if (isset($_GET['action']) && $_GET['action'] === 'logout') {
    session_destroy();
    header("Location: index.php");
    exit;
}

/* register */

if (isset($_POST['register'])) {
    $nom      = trim($_POST['nom'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($nom === '' || $password === '') {
        $message = "Merci de remplir tous les champs pour l'inscription.";
    } else {
        // Vérifier si le nom d'utilisateur existe déjà
        $existing = getUserByNom($pdo, $nom);
        if ($existing) {
            $message = "Ce nom d'utilisateur est déjà pris.";
        } else {
            // Si aucun admin n'existe encore, cette inscription devient admin
            $isFirstAdmin = !firstAdminExists($pdo);
            $role = $isFirstAdmin ? 'admin' : 'visiteur';

            $hash = password_hash($password, PASSWORD_BCRYPT);

            // pas supprimer sinon bug j'ai pas réussis à fix ça
            $sql = "INSERT INTO utilisateur (nom, email, mdp, role)
                    VALUES (:n, '', :m, :r)";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':n' => $nom,
                ':m' => $hash,
                ':r' => $role
            ]);

            $_SESSION['user_id'] = $pdo->lastInsertId();
            header("Location: index.php");
            exit;
        }
    }
}

/* login */

if (isset($_POST['login'])) {
    $nom      = trim($_POST['nom'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($nom === '' || $password === '') {
        $message = "Merci de remplir tous les champs pour la connexion.";
    } else {
        $user = getUserByNom($pdo, $nom);
        if ($user && password_verify($password, $user['mdp'])) {
            $_SESSION['user_id'] = $user['id_utilisateur'];
            header("Location: index.php");
            exit;
        } else {
            $message = "Identifiants incorrects.";
        }
    }
}

/* current user */

$currentUser = getCurrentUser($pdo);
if ($currentUser) {
    $isAdmin = ($currentUser['role'] === 'admin');
}

/* ajout citation */

if (isset($_POST['add_quote']) && $currentUser) {
    $content = trim($_POST['content'] ?? '');
    if ($content === '') {
        $message = "La citation ne peut pas être vide.";
    } else {
        $sql = "INSERT INTO citation (texte, auteur, date_creation, id_utilisateur)
                VALUES (:t, :a, NOW(), :uid)";
        $stmt = $pdo->prepare($sql);
        $stmt->execute([
            ':t'   => $content,
            ':a'   => $currentUser['nom'],
            ':uid' => $currentUser['id_utilisateur']
        ]);
        $message = "Citation ajoutée.";
    }
}

/* admin crud */

if ($isAdmin) {
    // Modifier une citation
    if (isset($_POST['edit_quote'])) {
        $citationId = (int)($_POST['citation_id'] ?? 0);
        $content    = trim($_POST['content'] ?? '');

        if ($citationId > 0 && $content !== '') {
            $sql = "UPDATE citation SET texte = :t WHERE id_citation = :id";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([
                ':t'  => $content,
                ':id' => $citationId
            ]);
            $message = "Citation modifiée.";
        }
    }

    // Supprimer une citation
    if (isset($_POST['delete_quote'])) {
        $citationId = (int)($_POST['citation_id'] ?? 0);
        if ($citationId > 0) {
            $sql = "DELETE FROM citation WHERE id_citation = :id";
            $stmt = $pdo->prepare($sql);
            $stmt->execute([':id' => $citationId]);
            $message = "Citation supprimée.";
        }
    }

    // Supprimer toutes les citations
    if (isset($_POST['delete_all_quotes'])) {
        $pdo->exec("DELETE FROM citation");
        $message = "Toutes les citations ont été supprimées.";
    }
}

/* récup citations carourou */

$sliderQuotesStmt = $pdo->query("
    SELECT 
        c.id_citation,
        c.texte,
        c.auteur,
        c.date_creation,
        u.nom AS nom_utilisateur
    FROM citation c
    LEFT JOIN utilisateur u ON c.id_utilisateur = u.id_utilisateur
    ORDER BY c.date_creation DESC
    LIMIT 6
");
$sliderQuotes = $sliderQuotesStmt->fetchAll(PDO::FETCH_ASSOC);

/* récup citations admin */

$allQuotes = [];
if ($isAdmin) {
    $allQuotesStmt = $pdo->query("
        SELECT 
            c.id_citation,
            c.texte,
            c.auteur,
            c.date_creation,
            u.nom AS nom_utilisateur
        FROM citation c
        LEFT JOIN utilisateur u ON c.id_utilisateur = u.id_utilisateur
        ORDER BY c.date_creation DESC
    ");
    $allQuotes = $allQuotesStmt->fetchAll(PDO::FETCH_ASSOC);
}

?>
<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>Site de citations</title>
    <link rel="stylesheet" href="style.css">
</head>
<body>
    <!-- Overlay sombre pour lisibilité -->
    <div class="overlay"></div>

    <div class="page-wrapper">
        <!-- header et auth -->
        <header class="top-bar">
            <div class="logo-title">
                <h1>Citations</h1>
                <p class="subtitle">Un mot, une pensée, un instant.</p>
            </div>

            <div class="auth-box">
                <?php if ($currentUser): ?>
                    <div class="user-info">
                        <span>
                            Connecté en tant que 
                            <strong><?php echo htmlspecialchars($currentUser['nom']); ?></strong>
                            <?php if ($isAdmin): ?>
                                <span class="badge-admin">ADMIN</span>
                            <?php endif; ?>
                        </span>
                        <a class="btn-logout" href="index.php?action=logout">Se déconnecter</a>
                    </div>
                <?php else: ?>
                    <div class="tabs">
                        <!-- RADIO LOGIN -->
                        <input type="radio" id="tab-login" name="tab-auth" checked>
                        <label for="tab-login">Connexion</label>

                        <!-- RADIO REGISTER -->
                        <input type="radio" id="tab-register" name="tab-auth">
                        <label for="tab-register">Inscription</label>

                        <div class="tab-content">
                            <!-- FORMULAIRE LOGIN (NOM + MDP) -->
                            <form method="post" class="auth-form" autocomplete="off">
                                <input type="text" name="nom" placeholder="Nom d'utilisateur">
                                <input type="password" name="password" placeholder="Mot de passe">
                                <button type="submit" name="login">Se connecter</button>
                            </form>

                            <!-- FORMULAIRE REGISTER (NOM + MDP) -->
                            <form method="post" class="auth-form" autocomplete="off">
                                <input type="text" name="nom" placeholder="Nom d'utilisateur">
                                <input type="password" name="password" placeholder="Mot de passe">
                                <button type="submit" name="register">Créer un compte</button>
                            </form>
                        </div>
                    </div>
                <?php endif; ?>
            </div>
        </header>

        <!-- MESSAGE GLOBAL -->
        <?php if ($message !== ""): ?>
            <div class="flash-message">
                <?php echo htmlspecialchars($message); ?>
            </div>
        <?php endif; ?>

        <!-- main -->
        <main class="main-content">

            <!-- SECTION CITATION (CARROUSEL) -->
            <section class="quotes-section">
                <h2>Citation du moment</h2>

                <?php if (count($sliderQuotes) === 0): ?>
                    <p class="empty-info">
                        Aucune citation pour l'instant. Connecte-toi et sois le premier à en poster !
                    </p>
                <?php else: ?>
                    <div class="quote-carousel">
                        <?php
                        $index = 0;
                        foreach ($sliderQuotes as $q):
                            $index++;
                            $auteur = $q['auteur'];
                            if ($auteur === null || $auteur === '') {
                                $auteur = $q['nom_utilisateur'] ?: 'Anonyme';
                            }
                        ?>
                            <div class="quote-slide slide-<?php echo $index; ?>">
                                <p class="quote-text">
                                    “<?php echo htmlspecialchars($q['texte']); ?>”
                                </p>
                                <p class="quote-meta">
                                    — <?php echo htmlspecialchars($auteur); ?>
                                    <?php if (!empty($q['date_creation'])): ?>
                                        <span class="date">
                                            (<?php echo htmlspecialchars($q['date_creation']); ?>)
                                        </span>
                                    <?php endif; ?>
                                </p>
                            </div>
                        <?php endforeach; ?>
                    </div>
                <?php endif; ?>

                <!-- FORMULAIRE NOUVELLE CITATION -->
                <?php if ($currentUser): ?>
                    <form method="post" class="quote-form">
                        <textarea name="content" rows="3" placeholder="Écris ta citation ici..."></textarea>
                        <button type="submit" name="add_quote">Publier la citation</button>
                    </form>
                <?php else: ?>
                    <p class="login-reminder">
                        Connecte-toi ou crée un compte pour poster une citation.
                    </p>
                <?php endif; ?>
            </section>

            <!-- SECTION ADMIN (LISTE COMPLÈTE) -->
            <?php if ($isAdmin): ?>
                <section class="admin-section">
                    <div class="admin-header">
                        <h2>Administration des citations</h2>
                        <?php if (!empty($allQuotes)): ?>
                            <form method="post" onsubmit="return confirm('Supprimer TOUTES les citations ?');">
                                <button type="submit" name="delete_all_quotes" class="btn-danger">
                                    Supprimer toutes les citations
                                </button>
                            </form>
                        <?php endif; ?>
                    </div>

                    <?php if (empty($allQuotes)): ?>
                        <p class="empty-info">Aucune citation en base.</p>
                    <?php else: ?>
                        <div class="admin-table">
                            <?php foreach ($allQuotes as $q): ?>
                                <div class="admin-row">
                                    <form method="post" class="admin-quote-form">
                                        <input type="hidden" name="citation_id"
                                               value="<?php echo (int)$q['id_citation']; ?>">

                                        <textarea name="content" rows="2"><?php
                                            echo htmlspecialchars($q['texte']);
                                        ?></textarea>

                                        <div class="admin-meta">
                                            <span>
                                                Par <strong><?php echo htmlspecialchars($q['nom_utilisateur'] ?: 'Anonyme'); ?></strong>
                                                <?php if (!empty($q['date_creation'])): ?>
                                                    • <?php echo htmlspecialchars($q['date_creation']); ?>
                                                <?php endif; ?>
                                            </span>
                                            <div class="admin-actions">
                                                <button type="submit" name="edit_quote">Modifier</button>
                                                <button type="submit" name="delete_quote" class="btn-danger"
                                                        onclick="return confirm('Supprimer cette citation ?');">
                                                    Supprimer
                                                </button>
                                            </div>
                                        </div>
                                    </form>
                                </div>
                            <?php endforeach; ?>
                        </div>
                    <?php endif; ?>
                </section>
            <?php endif; ?>

        </main>
    </div>
</body>
</html>

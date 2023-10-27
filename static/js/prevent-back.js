// Verifica si el usuario está autenticado o no.
var isAuthenticated = false; // Debes establecer esto en `true` si el usuario está autenticado.

// Controla el historial de navegación.
if (!isAuthenticated) {
    // Si el usuario no está autenticado, evita que retroceda al inicio.
    window.history.pushState(null, null, window.location.href);
    window.onpopstate = function (event) {
        window.history.pushState(null, null, window.location.href);
    };
}
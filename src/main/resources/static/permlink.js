function buildPermlink() {
    var params = new URLSearchParams();
    var fields = ['scopes', 'acrValues', 'uiLocales', 'authorizationDetails', 'prompt'];
    fields.forEach(function(field) {
        var input = document.getElementById(field);
        if (input && input.value && input.value.trim()) {
            params.set(field, input.value.trim());
        }
    });
    var query = params.toString();
    return window.location.origin + '/' + (query ? '?' + query : '');
}

function togglePermlink() {
    var section = document.getElementById('permlinkSection');
    var urlInput = document.getElementById('permlinkUrl');
    if (section.style.display === 'none') {
        urlInput.value = buildPermlink();
        section.style.display = 'block';
    } else {
        section.style.display = 'none';
    }
}

function copyPermlink() {
    var urlInput = document.getElementById('permlinkUrl');
    urlInput.value = buildPermlink();
    navigator.clipboard.writeText(urlInput.value);
}

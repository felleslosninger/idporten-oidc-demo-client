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
    return window.location.origin + '/idporten-oidc-demo-client?' + query;
}

function copyPermlink() {
    var url = buildPermlink();
    if (navigator.clipboard) {
        navigator.clipboard.writeText(url);
    } else {
        const temp = document.createElement('textarea');
        temp.setAttribute("copytext", url);
        copyToClipboard(temp)
    }
}

document.getElementById('permlink-button').addEventListener('click', copyPermlink);

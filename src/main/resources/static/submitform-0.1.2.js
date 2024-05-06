window.onload = function() {
    var formElement = document.getElementsByTagName("form")[0];
    if(formElement) {
        var formData = new FormData(formElement);
        if (Array.from(formData.entries()).length > 0) {
            formElement.submit();
        } else {
            window.location = formElement.action;
        }
    }
}

function copyToClipboard(element) {
    if (!navigator.clipboard){
        const temp = document.createElement('textarea');
        temp.value = element.getAttribute('copytext');
        document.body.appendChild(temp);
        temp.select();
        document.execCommand('copy');
        document.body.removeChild(temp);
    } else{
        navigator.clipboard.writeText(element.getAttribute('copytext')).then(
            () => { /* success: do nothing */},
            () => { alert("Could not copy to clipboard. You might not have necessary permissions.")}
        );
    }    
}


var btns = document.getElementsByClassName("bi-clipboard-plus");
for( i = 0; i < btns.length; i++){
    btns[i].addEventListener("click", function(){copyToClipboard(this)});
}

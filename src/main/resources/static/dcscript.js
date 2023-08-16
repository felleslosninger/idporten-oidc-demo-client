
function copyToClipboard(element) {
    const temp = document.createElement('textarea');
    temp.value = element.getAttribute('copytext');
    document.body.appendChild(temp);
    temp.select();
    if (!navigator.clipboard){
        document.execCommand('copy');
    } else{
        navigator.clipboard.writeText(text_to_copy);
    }    
    document.body.removeChild(temp);
}


var btns = document.getElementsByClassName("bi-clipboard-plus");
for( i = 0; i < btns.length; i++){
    btns[i].addEventListener("click", function(){copyToClipboard(this)});
}

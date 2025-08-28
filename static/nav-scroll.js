let prevScrollpos = window.pageYOffset;

window.onscroll = function() {
    const currentScrollPos = window.pageYOffset;
    const navbar = document.querySelector('.navbar');
    
    if (prevScrollpos > currentScrollPos) {
        navbar.style.top = "0";
    } else {
        navbar.style.top = "-60px";  // slightly more than navbar height
    }
    prevScrollpos = currentScrollPos;
}

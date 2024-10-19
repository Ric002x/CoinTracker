document.addEventListener('DOMContentLoaded', () => {
    const showNavItens = document.getElementById('showNavItens');
    const navItens = document.getElementById('navItens');

    showNavItens.addEventListener('click', () => {
        navItens.classList.toggle('active')
        showNavItens.classList.toggle('active')
    })
})
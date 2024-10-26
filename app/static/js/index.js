document.addEventListener('DOMContentLoaded', () => {
    const showNavItens = document.getElementById('showNavItems');
    const navItens = document.getElementById('navItems');

    showNavItens.addEventListener('click', () => {
        navItens.classList.toggle('active')
        showNavItens.classList.toggle('active')
    })
})

document.addEventListener('DOMContentLoaded', () => {
    const logoutButton = document.getElementById('logoutButton');
    
    logoutButton.addEventListener("click", (event) => {
        event.preventDefault();

        const user_confirm = confirm("Deseja executar o logout?")

        if (user_confirm) {
            window.location.href = '/logout';
        }
    })
})

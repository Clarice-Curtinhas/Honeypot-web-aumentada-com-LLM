document.getElementById('chatForm').addEventListener('submit', async function(e) {
    e.preventDefault();

    const inputField = document.getElementById('userInput');
    const respostaDiv = document.getElementById('resposta');
    const promptValue = inputField.value.trim();

    if (!promptValue) return;

    // 1) Mostra a mensagem de espera ANTES de enviar o pedido
    respostaDiv.textContent = 'Processando o seu pedido no modelo...';
    respostaDiv.classList.add('carregando');
    inputField.disabled = true;

    try {
        // 2) Envia o prompt e espera o servidor (LLM) responder
        const response = await fetch('/api/perguntar', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ prompt: promptValue })
        });

        const data = await response.json();

        // Servidor pediu redirecionamento (ex.: LLM falhou -> página de login)
        if (data.status === 'redirect') {
            window.location.href = data.url;
            return;
        }

        // 3) Substitui a página inteira pelo HTML gerado pela LLM, dentro de um iframe
        //    sandbox vazio: o HTML/CSS é renderizado, mas nenhum script roda, formulários
        //    não enviam nada e o conteúdo não tem acesso à nossa origem
        const iframe = document.createElement('iframe');
        iframe.sandbox = '';
        iframe.srcdoc = data.resposta;
        iframe.style.cssText = 'position:fixed;inset:0;width:100vw;height:100vh;border:0;background:#fff';
        document.body.replaceChildren(iframe);

    } catch (error) {
        console.error('Erro ao enviar a requisição:', error);
        respostaDiv.textContent = 'Erro ao processar o pedido.';
    } finally {
        respostaDiv.classList.remove('carregando');
        inputField.disabled = false;
        inputField.focus();
    }
});

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

        // 3) Substitui a mensagem de espera pela resposta do servidor
        //    (textContent e não innerHTML, para não executar HTML vindo da resposta)
        respostaDiv.textContent = data.resposta;
        inputField.value = '';

    } catch (error) {
        console.error('Erro ao enviar a requisição:', error);
        respostaDiv.textContent = 'Erro ao processar o pedido.';
    } finally {
        respostaDiv.classList.remove('carregando');
        inputField.disabled = false;
        inputField.focus();
    }
});

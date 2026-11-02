document.getElementById('chatForm').addEventListener('submit', async function(e) { 
    e.preventDefault();

    const inputField = document.getElementById('userInput');
    const promptValue = inputField.value.trim();

    if (!promptValue) return;

    try {
        // Envia os dados para a rota do servidor Flask
        const response = await fetch('/api/perguntar', {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ prompt: promptValue })
        });

       // const data = await response.json();
        
        // Limpa o campo após o envio
        inputField.value = '';

        // Exemplo: Feedback ou resposta simulada da IA
        //console.log('Resposta do Honeypot:', data);

    } catch (error) {
        console.error('Erro ao enviar a requisição:', error);
    }
});
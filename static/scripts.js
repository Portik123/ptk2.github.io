
async function fetchAddons() {
    try {
        const response = await fetch('/api/addons');
        const addons = await response.json();
        const tableBody = document.getElementById('addonTable');
        tableBody.innerHTML = '';
        addons.forEach(addon => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td><span class="tag ${addon.type === 'Folder' ? 'tag-folder' : ''}">[${addon.type}]</span> ${addon.title}</td>
                <td><a href="${addon.link}" target="_blank">Открыть ссылку</a></td>
                <td class="type-${addon.type.toLowerCase()}">${addon.type}</td>
                <td>${addon.tags || 'Нет тегов'}</td>
            `;
            tableBody.appendChild(row);
        });
    } catch (error) {
        console.error('Ошибка загрузки аддонов:', error);
    }
}

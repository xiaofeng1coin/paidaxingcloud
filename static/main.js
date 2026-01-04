function switchView(viewName) {
    const container = document.getElementById('fileContainer');
    const btnList = document.getElementById('btnList');
    const btnGrid = document.getElementById('btnGrid');
    if (viewName === 'list') {
        container.classList.remove('grid-view'); container.classList.add('list-view');
        btnList.classList.add('active'); btnGrid.classList.remove('active');
    } else {
        container.classList.remove('list-view'); container.classList.add('grid-view');
        btnList.classList.remove('active'); btnGrid.classList.add('active');
    }
}
function filterType(type, element) {
    document.querySelectorAll('.nav-item').forEach(el => el.classList.remove('active'));
    element.classList.add('active');
    const items = document.querySelectorAll('.file-item');
    items.forEach(item => {
        const itemType = item.getAttribute('data-type');
        if (type === 'all' || itemType === 'folder' || itemType === type) {
            item.style.display = (document.getElementById('fileContainer').classList.contains('grid-view')) ? 'flex' : 'grid';
        } else { item.style.display = 'none'; }
    });
    document.getElementById('selectAll').checked = false;
    clearSelection();
}
document.getElementById('searchInput').addEventListener('input', function(e) {
    const val = e.target.value.toLowerCase();
    const items = document.querySelectorAll('.file-item');
    items.forEach(item => {
        const name = item.getAttribute('data-name').toLowerCase();
        if (name.includes(val)) {
            item.style.display = (document.getElementById('fileContainer').classList.contains('grid-view')) ? 'flex' : 'grid';
        } else { item.style.display = 'none'; }
    });
});
function updateSelectionBar() {
    const checkboxes = document.querySelectorAll('.item-checkbox:checked');
    const count = checkboxes.length;
    const bar = document.getElementById('selectionBar');
    document.getElementById('selectCount').innerText = count;
    if (count > 0) bar.classList.add('active');
    else { bar.classList.remove('active'); const sa = document.getElementById('selectAll'); if(sa) sa.checked = false; }
}
function updateSelectionUI(checkbox) {
    const fileItem = checkbox.closest('.file-item');
    if (checkbox.checked) fileItem.classList.add('selected');
    else fileItem.classList.remove('selected');
    updateSelectionBar();
}
function toggleSelectAll(selectAllBox) {
    const checkboxes = document.querySelectorAll('.item-checkbox');
    checkboxes.forEach(cb => {
        const fileItem = cb.closest('.file-item');
        if (fileItem.style.display !== 'none' && !cb.disabled) {
            cb.checked = selectAllBox.checked;
            updateSelectionUI(cb);
        }
    });
}
function clearSelection() {
    const checkboxes = document.querySelectorAll('.item-checkbox');
    checkboxes.forEach(cb => { cb.checked = false; updateSelectionUI(cb); });
    const sa = document.getElementById('selectAll'); if(sa) sa.checked = false;
}
function downloadSelectedFiles() {
    const checkboxes = document.querySelectorAll('.item-checkbox:checked');
    if (checkboxes.length === 0) return;
    if (checkboxes.length > 5) {
        if (!confirm(`即将下载 ${checkboxes.length} 个文件。请允许浏览器“自动下载”权限。`)) return;
    }
    checkboxes.forEach((cb, index) => {
        setTimeout(() => { triggerDownload(cb.value); }, index * 800);
    });
}
function triggerDownload(url) {
    const link = document.createElement('a');
    link.href = url;
    link.setAttribute('download', '');
    link.style.display = 'none';
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}
function openPreview(name, type, viewUrl, downloadUrl) {
    const modal = document.getElementById('previewModal');
    const container = document.getElementById('previewContent');
    document.getElementById('previewTitle').innerText = name;
    document.getElementById('previewDl').href = downloadUrl;
    modal.classList.add('active');
    container.innerHTML = '<div style="color:white">加载中...</div>';
    if (type === 'image') container.innerHTML = `<img src="${viewUrl}" class="preview-media" style="object-fit:contain;">`;
    else if (type === 'video') container.innerHTML = `<video controls autoplay class="preview-media"><source src="${viewUrl}"></video>`;
    else if (type === 'code' || type === 'text') fetch(viewUrl).then(r => r.text()).then(txt => { container.innerHTML = `<pre style="color:#ccc; padding:20px; width:100%; white-space:pre-wrap;">${txt.replace(/</g,"&lt;")}</pre>`; });
    else if (type === 'doc') container.innerHTML = `<iframe src="${viewUrl}" style="width:100%; height:100%; border:none;"></iframe>`;
    else container.innerHTML = `<div style="color:#fff; text-align:center;"><p>此文件不支持在线预览</p></div>`;
}
const qrCodeObj = new QRCode(document.getElementById("qrcode"), { width: 150, height: 150 });
function showQR(url) {
    qrCodeObj.clear();
    qrCodeObj.makeCode(url);
    document.getElementById('qrModal').classList.add('active');
}
function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    if(id === 'previewModal') document.getElementById('previewContent').innerHTML = '';
}

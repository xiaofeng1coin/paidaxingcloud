console.log("Main.js Loaded v3.5");

// 基础视图和选择功能
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

// 下载功能
function downloadSelectedFiles() {
    const checkboxes = document.querySelectorAll('.item-checkbox:checked');
    if (checkboxes.length === 0) return;
    checkboxes.forEach((cb, index) => {
        // 只下载非文件夹
        const url = cb.getAttribute('data-url');
        if(url) setTimeout(() => { triggerDownload(url); }, index * 800);
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

// 预览功能
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

// ================= 管理功能 =================

function getPath() { return document.getElementById('currentPath').value; }

// --- 新建文件夹 ---
function createNewFolder() {
    document.getElementById('mkdirModal').style.display = 'flex';
    document.getElementById('newFolderName').focus();
}
function closeMkdirModal() {
    document.getElementById('mkdirModal').style.display = 'none';
    document.getElementById('newFolderName').value = '';
}
function submitMkdir() {
    const name = document.getElementById('newFolderName').value.trim();
    if (!name) { alert("名称不能为空"); return; }
    closeMkdirModal();
    fetch('/admin/file/mkdir', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ path: getPath(), name: name })
    }).then(r => r.json()).then(data => {
        if(data.success) window.location.reload();
        else alert("创建失败: " + data.error);
    });
}

// --- 上传文件 ---
function triggerUpload() { document.getElementById('uploadInput').click(); }
const uploadInputEl = document.getElementById('uploadInput');
if(uploadInputEl) {
    uploadInputEl.addEventListener('change', function(e) {
        if (this.files.length === 0) return;
        const formData = new FormData();
        formData.append('path', getPath());
        for (let i = 0; i < this.files.length; i++) formData.append('files', this.files[i]);
        
        const modal = document.getElementById('uploadProgressModal');
        const bar = document.getElementById('progressBar');
        const txtPercent = document.getElementById('uploadPercent');
        const txtSpeed = document.getElementById('uploadSpeed');
        modal.style.display = 'flex';
        
        const xhr = new XMLHttpRequest();
        const startTime = new Date().getTime();
        xhr.upload.onprogress = function(event) {
            if (event.lengthComputable) {
                const percent = (event.loaded / event.total) * 100;
                bar.style.width = percent + "%";
                txtPercent.innerText = Math.round(percent) + "%";
                const now = new Date().getTime();
                const duration = (now - startTime) / 1000;
                if (duration > 0) txtSpeed.innerText = formatSpeed(event.loaded / duration);
            }
        };
        xhr.onload = function() {
            if (xhr.status === 200) {
                const resp = JSON.parse(xhr.responseText);
                if (resp.success) window.location.reload();
                else { alert("上传失败: " + resp.error); modal.style.display = 'none'; }
            } else { alert("服务器错误"); modal.style.display = 'none'; }
        };
        xhr.onerror = function() { alert("网络错误"); modal.style.display = 'none'; };
        xhr.open("POST", "/admin/file/upload");
        xhr.send(formData);
    });
}
function formatSpeed(bytesPerSec) {
    if (bytesPerSec > 1024 * 1024) return (bytesPerSec / 1024 / 1024).toFixed(1) + " MB/s";
    return (bytesPerSec / 1024).toFixed(1) + " KB/s";
}

// --- 重命名 ---
function openRenameModal(oldName) {
    document.getElementById('renameModal').style.display = 'flex';
    document.getElementById('renameOldName').value = oldName;
    document.getElementById('renameNewName').value = oldName;
    document.getElementById('renameNewName').focus();
}
function closeRenameModal() { document.getElementById('renameModal').style.display = 'none'; }
function submitRename() {
    const oldName = document.getElementById('renameOldName').value;
    const newName = document.getElementById('renameNewName').value.trim();
    if (!newName || newName === oldName) { closeRenameModal(); return; }
    
    fetch('/admin/file/rename', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ path: getPath(), old_name: oldName, new_name: newName })
    }).then(r => r.json()).then(data => {
        if(data.success) window.location.reload();
        else alert("重命名失败: " + data.error);
    });
}

// --- 删除 (已修改为自定义弹窗) ---
let currentDeleteFiles = []; // 全局变量，用于存储待删除文件

function deleteSingle(name) {
    currentDeleteFiles = [name];
    document.getElementById('deleteConfirmMsg').innerHTML = `确定要删除 "<b>${name}</b>" 吗？<br><span style="font-size:12px; color:#6b7280;">此操作不可恢复。</span>`;
    document.getElementById('deleteFileModal').style.display = 'flex';
}

function deleteSelectedFiles() {
    const filenames = Array.from(document.querySelectorAll('.item-checkbox:checked')).map(cb => cb.value);
    if(filenames.length === 0) return;
    
    currentDeleteFiles = filenames;
    document.getElementById('deleteConfirmMsg').innerText = `确定要删除选中的 ${filenames.length} 个项目吗？`;
    document.getElementById('deleteFileModal').style.display = 'flex';
}

function closeDeleteFileModal() {
    document.getElementById('deleteFileModal').style.display = 'none';
    currentDeleteFiles = [];
}

function executeFileDelete() {
    if (currentDeleteFiles.length === 0) return;
    closeDeleteFileModal();
    doDelete(currentDeleteFiles);
}

function doDelete(filenames) {
    fetch('/admin/file/delete', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({ path: getPath(), filenames: filenames })
    }).then(r => r.json()).then(data => {
        if(data.success) window.location.reload();
        else alert("删除失败: " + (data.msg || data.error));
    });
}

// --- 分享 (保持原有) ---
function openShareModal(relPath, fileName) {
    document.getElementById('shareModal').classList.add('active');
    document.getElementById('shareFilePath').value = relPath;
    document.getElementById('shareFileName').innerText = fileName;
    document.getElementById('shareSlug').value = '';
    document.getElementById('shareResult').style.display = 'none';
    document.getElementById('shareError').style.display = 'none';
    document.getElementById('btnCreateShare').style.display = 'block';
    document.getElementById('btnCreateShare').disabled = false;
    document.getElementById('btnCreateShare').innerText = '立即生成';
}
function submitShare() {
    const btn = document.getElementById('btnCreateShare');
    const path = document.getElementById('shareFilePath').value;
    const slug = document.getElementById('shareSlug').value;
    const duration = document.getElementById('shareDuration').value;
    btn.disabled = true; btn.innerText = '生成中...';
    document.getElementById('shareError').style.display = 'none';
    
    fetch('/admin/share/create', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ file_path: path, slug: slug, duration: duration })
    }).then(r => r.json()).then(data => {
        if (data.error) throw new Error(data.error);
        document.getElementById('shareResult').style.display = 'block';
        document.getElementById('shareUrlResult').value = data.url;
        btn.style.display = 'none';
    }).catch(err => {
        document.getElementById('shareError').innerText = err.message;
        document.getElementById('shareError').style.display = 'block';
        btn.disabled = false; btn.innerText = '立即生成';
    });
}
function copyShareLink() {
    const input = document.getElementById("shareUrlResult");
    input.select(); 
    if(navigator.clipboard && window.isSecureContext) navigator.clipboard.writeText(input.value).then(() => alert("已复制"));
    else { document.execCommand('copy'); alert("已复制"); }
}
const qrCodeObj = new QRCode(document.getElementById("qrcode"), { width: 150, height: 150 });
function showQR(url) {
    qrCodeObj.clear(); qrCodeObj.makeCode(url);
    document.getElementById('qrModal').classList.add('active');
}
function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    if(id === 'previewModal') document.getElementById('previewContent').innerHTML = '';
}

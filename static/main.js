// ================= CSRF 安全修复(P0-5) =================
// token 由模板 head 的 meta 标签注入，与后端会话绑定
function getCsrf() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function getCsrfHeaders() {
    return {'X-CSRF-Token': getCsrf(), 'Accept': 'application/json'};
}

// ================= 基础视图和选择功能 =================

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
    // 重置选择状态
    const selectAllBox = document.getElementById('selectAll');
    if(selectAllBox) selectAllBox.checked = false;
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
        // 只选中当前可见且未被禁用的
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

// ================= 下载功能 =================

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

// ================= 预览功能 =================

function openPreview(name, type, viewUrl, downloadUrl) {
    const modal = document.getElementById('previewModal');
    const container = document.getElementById('previewContent');
    document.getElementById('previewTitle').innerText = name;
    document.getElementById('previewDl').href = downloadUrl;
    modal.classList.add('active');
    
    container.innerHTML = '<div style="color:white; text-align:center; padding:20px;">加载中...</div>';
    
    if (type === 'image') container.innerHTML = `<img src="${viewUrl}" class="preview-media" style="object-fit:contain;">`;
    else if (type === 'video') container.innerHTML = `<video controls autoplay class="preview-media"><source src="${viewUrl}"></video>`;
    else if (type === 'code' || type === 'text') {
        fetch(viewUrl).then(r => r.text()).then(txt => { 
            container.innerHTML = `<pre style="color:#ccc; padding:20px; width:100%; white-space:pre-wrap; overflow:auto;">${txt.replace(/</g,"&lt;")}</pre>`; 
        }).catch(e => {
            container.innerHTML = `<div style="color:red; text-align:center;">加载文本失败</div>`;
        });
    }
    else if (type === 'doc') container.innerHTML = `<iframe src="${viewUrl}" style="width:100%; height:100%; border:none;"></iframe>`;
    else container.innerHTML = `<div style="color:#fff; text-align:center; padding:40px;"><i class="fa-regular fa-file" style="font-size:48px; margin-bottom:20px;"></i><p>此文件不支持在线预览</p></div>`;
}

// ================= 管理功能 (需要登录) =================

function getPath() { return document.getElementById('currentPath').value; }

// --- 1. 新建文件夹 ---
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
        headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
        body: JSON.stringify({ path: getPath(), name: name })
    }).then(r => r.json()).then(data => {
        if(data.success) window.location.reload();
        else alert("创建失败: " + data.error);
    });
}

// --- 2. 上传文件 (增强错误提示版) ---
function triggerUpload() { document.getElementById('uploadInput').click(); }

const uploadInputEl = document.getElementById('uploadInput');
if(uploadInputEl) {
    uploadInputEl.addEventListener('change', function(e) {
        if (this.files.length === 0) return;
        
        const formData = new FormData();
        formData.append('path', getPath());
        for (let i = 0; i < this.files.length; i++) formData.append('files', this.files[i]);
        this.value = ''; // 优化(P2-10)：清空 input，上传失败后可重选同一文件（change 需要值变化才触发）

        const modal = document.getElementById('uploadProgressModal');
        const bar = document.getElementById('progressBar');
        const txtPercent = document.getElementById('uploadPercent');
        const txtSpeed = document.getElementById('uploadSpeed');
        
        // 重置进度条
        bar.style.width = "0%";
        txtPercent.innerText = "0%";
        txtSpeed.innerText = "准备中...";
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
                try {
                    const resp = JSON.parse(xhr.responseText);
                    if (resp.success) {
                        window.location.reload();
                    } else {
                        alert("上传失败: " + resp.error);
                        modal.style.display = 'none';
                    }
                } catch(e) {
                    alert("上传成功但服务器返回格式错误，请刷新页面查看");
                    modal.style.display = 'none';
                    window.location.reload();
                }
            } else {
                // === 详细错误处理逻辑 ===
                let errorMsg = "服务器内部错误 (" + xhr.status + ")";
                
                // 1. 尝试解析后端返回的 JSON 错误
                try {
                    const resp = JSON.parse(xhr.responseText);
                    if (resp.error) errorMsg = "上传出错: " + resp.error;
                } catch (e) {
                    // 2. 如果不是 JSON，根据状态码猜测原因 (Nginx/Gateway 拦截)
                    if (xhr.status === 413) {
                        errorMsg = "上传失败：文件大小超过服务器限制 (413 Entity Too Large)";
                    } else if (xhr.status === 502) {
                        errorMsg = "网关错误 (502 Bad Gateway) - 可能是上传超时或后端重启";
                    } else if (xhr.status === 504) {
                        errorMsg = "上传超时 (504 Gateway Timeout)";
                    } else if (xhr.status === 403) {
                        errorMsg = "拒绝访问 (403 Forbidden) - 可能没有写入权限或Token过期";
                    } else {
                        errorMsg += " " + xhr.statusText;
                    }
                }
                
                alert(errorMsg);
                modal.style.display = 'none';
            }
        };

        xhr.onerror = function() {
            alert("网络连接失败，请检查网络或服务器状态");
            modal.style.display = 'none';
        };

        xhr.open("POST", "/admin/file/upload");
        xhr.setRequestHeader("X-CSRF-Token", getCsrf());
        xhr.send(formData);
    });
}

function formatSpeed(bytesPerSec) {
    if (bytesPerSec > 1024 * 1024) return (bytesPerSec / 1024 / 1024).toFixed(1) + " MB/s";
    return (bytesPerSec / 1024).toFixed(1) + " KB/s";
}

// --- 3. 重命名 ---
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
        headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
        body: JSON.stringify({ path: getPath(), old_name: oldName, new_name: newName })
    }).then(r => r.json()).then(data => {
        if(data.success) window.location.reload();
        else alert("重命名失败: " + data.error);
    });
}

// --- 4. 删除 (包含单个和批量) ---
let currentDeleteFiles = []; 

function deleteSingle(name) {
    currentDeleteFiles = [name];
    // 安全修复(P1-2)：改用 DOM API，文件名不再进入 innerHTML
    const msg = document.getElementById('deleteConfirmMsg');
    msg.textContent = '';
    const line1 = document.createElement('div');
    line1.textContent = `确定要删除 "${name}" 吗？`;
    const line2 = document.createElement('span');
    line2.textContent = '此操作不可恢复。';
    line2.style.cssText = 'font-size:12px; color:#6b7280;';
    msg.appendChild(line1);
    msg.appendChild(line2);
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
    // 使用解构来深克隆数组，解决弹窗关闭引起的清空问题
    const files = [...currentDeleteFiles];
    closeDeleteFileModal();
    doDelete(files);
}

function doDelete(filenames) {
    const payload = { path: getPath(), filenames: filenames };
    fetch('/admin/file/delete', {
        method: 'POST',
        headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
        body: JSON.stringify(payload)
    }).then(r => r.json()).then(data => {
        if(data.success) window.location.reload();
        else alert("删除失败: " + (data.msg || data.error));
    }).catch(err => {
        alert("网络错误或服务器异常");
    });
}

// --- 5. 分享 ---
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
        headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
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
    if(navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(input.value).then(() => alert("已复制"));
    } else { 
        document.execCommand('copy'); 
        alert("已复制"); 
    }
}

// --- 二维码 & 通用弹窗关闭 ---
// 确保 QRCode 库已加载，避免报错
let qrCodeObj = null;
if (typeof QRCode !== 'undefined') {
    qrCodeObj = new QRCode(document.getElementById("qrcode"), { width: 150, height: 150 });
}

function showQR(url) {
    if(qrCodeObj) {
        qrCodeObj.clear(); 
        qrCodeObj.makeCode(url);
        document.getElementById('qrModal').classList.add('active');
    } else {
        alert("二维码组件未加载");
    }
}

function closeModal(id) {
    document.getElementById(id).classList.remove('active');
    if(id === 'previewModal') document.getElementById('previewContent').innerHTML = '';
}

// ================= 安全修复(P1-2)：文件名不再嵌入 onclick 字符串，统一事件委托 =================
// 模板通过 data-* 属性传递参数，此处按 class 分发，杜绝 onclick 中的引号注入
document.addEventListener('DOMContentLoaded', function () {
    document.body.addEventListener('click', function (e) {
        const preview = e.target.closest('.preview-trigger');
        if (preview) { e.preventDefault(); openPreview(preview.dataset.name, preview.dataset.type, preview.dataset.view, preview.dataset.dl); return; }
        const qr = e.target.closest('.qr-trigger');
        if (qr) { showQR(qr.dataset.url); return; }
        const share = e.target.closest('.share-btn');
        if (share) { openShareModal(share.dataset.path, share.dataset.name); return; }
        const rename = e.target.closest('.rename-trigger');
        if (rename) { openRenameModal(rename.dataset.name); return; }
        const del = e.target.closest('.delete-trigger');
        if (del) { deleteSingle(del.dataset.name); return; }
    });
});
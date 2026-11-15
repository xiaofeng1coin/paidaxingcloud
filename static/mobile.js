// static/mobile.js

let currentItem = null; // 当前选中的文件对象 {name, path, isDir}

function getPath() { return document.getElementById('currentPath').value; }

// 优化(P2-11)：路径分段 URL 编码，文件名含 # ? 空格 中文时下载/预览不再 404
function safeUrl(prefix, relPath) {
    return prefix + relPath.split('/').map(encodeURIComponent).join('/');
}

// ================= CSRF 安全修复(P0-5) =================
// token 由模板 head 的 meta 标签注入，与后端会话绑定
function getCsrf() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : '';
}

function getCsrfHeaders() {
    return {'X-CSRF-Token': getCsrf(), 'Accept': 'application/json'};
}

// 点击列表项
function handleItemTap(name, relPath, isDir) {
    if (isDir) {
        // 如果是文件夹，直接进入 (带上 view=mobile 保持视图)
        window.location.href = safeUrl('/', relPath) + '?view=mobile';
    } else {
        // 如果是文件，打开操作菜单
        openActionSheet(name, relPath, isDir);
    }
}

// 打开底部菜单
function openActionSheet(name, relPath, isDir) {
    currentItem = { name, relPath, isDir };
    document.getElementById('sheetFilename').innerText = name;
    
    const overlay = document.getElementById('actionSheet');
    overlay.style.display = 'flex';
    // 强制重绘以触发 transition
    setTimeout(() => overlay.classList.add('active'), 10);
}

// 关闭底部菜单
function closeActionSheet() {
    const overlay = document.getElementById('actionSheet');
    overlay.classList.remove('active');
    setTimeout(() => {
        overlay.style.display = 'none';
        currentItem = null;
    }, 300); // 等待动画结束
}

// --- 动作执行 ---

function execDownload() {
    if(!currentItem) return;
    if(currentItem.isDir) { alert('手机端暂不支持文件夹打包下载'); return; }
    window.location.href = safeUrl('/download/', currentItem.relPath);
    closeActionSheet();
}

function execPreview() {
    if(!currentItem) return;
    if(currentItem.isDir) return;
    window.location.href = safeUrl('/view/', currentItem.relPath);
    closeActionSheet();
}

function execRename() {
    if(!currentItem) return;
    const newName = prompt("重命名文件:", currentItem.name);
    if(newName && newName !== currentItem.name) {
        fetch('/admin/file/rename', {
            method: 'POST',
            headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
            body: JSON.stringify({ 
                path: getPath(), 
                old_name: currentItem.name, 
                new_name: newName 
            })
        }).then(r => r.json()).then(data => {
            if(data.success) window.location.reload();
            else alert(data.error);
        });
    }
    closeActionSheet();
}

function execDelete() {
    if(!currentItem) return;
    if(confirm(`确定要删除 "${currentItem.name}" 吗?`)) {
        fetch('/admin/file/delete', {
            method: 'POST',
            headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
            body: JSON.stringify({ 
                path: getPath(), 
                filenames: [currentItem.name] 
            })
        }).then(r => r.json()).then(data => {
            if(data.success) window.location.reload();
            else alert(data.error || data.msg);
        });
    }
    closeActionSheet();
}

// --- 管理员菜单逻辑 ---

function toggleAdminMenu() {
    const menu = document.getElementById('adminMenu');
    if (menu.style.display === 'block') {
        menu.style.display = 'none';
    } else {
        menu.style.display = 'block';
    }
}

function createNewFolder() {
    toggleAdminMenu();
    const name = prompt("请输入新文件夹名称:");
    if(name) {
        fetch('/admin/file/mkdir', {
            method: 'POST',
            headers: Object.assign({'Content-Type': 'application/json'}, getCsrfHeaders()),
            body: JSON.stringify({ path: getPath(), name: name })
        }).then(r => r.json()).then(data => {
            if(data.success) window.location.reload();
            else alert(data.error);
        });
    }
}

function triggerUpload() {
    toggleAdminMenu();
    document.getElementById('mobileUploadInput').click();
}

const upInput = document.getElementById('mobileUploadInput');
if(upInput) {
    upInput.addEventListener('change', function() {
        if(this.files.length === 0) return;
        
        // 简单Loading提示
        const brand = document.querySelector('.brand');
        const oldHtml = brand.innerHTML;
        brand.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i> 上传中...';
        
        const formData = new FormData();
        formData.append('path', getPath());
        for (let i = 0; i < this.files.length; i++) formData.append('files', this.files[i]);
        this.value = ''; // 优化(P2-10)：上传失败后可重选同一文件

        fetch("/admin/file/upload", {
            method: "POST",
            headers: getCsrfHeaders(),
            body: formData
        }).then(r => r.json()).then(data => {
            if(data.success) window.location.reload();
            else {
                alert("上传失败: " + data.error);
                brand.innerHTML = oldHtml;
            }
        }).catch(() => {
            alert("网络错误");
            brand.innerHTML = oldHtml;
        });
    });
}

// ================= 安全修复(P1-2)：文件名不再嵌入 onclick 字符串，统一事件委托 =================
// 列表卡片与更多按钮通过 data-* 属性传参，此处按 class 分发
document.addEventListener('DOMContentLoaded', function () {
    document.body.addEventListener('click', function (e) {
        const more = e.target.closest('.item-more');
        if (more) {
            e.stopPropagation();
            openActionSheet(more.dataset.name, more.dataset.path, more.dataset.dir === 'true');
            return;
        }
        const card = e.target.closest('.item-card');
        if (card) {
            handleItemTap(card.dataset.name, card.dataset.path, card.dataset.dir === 'true');
        }
    });
});

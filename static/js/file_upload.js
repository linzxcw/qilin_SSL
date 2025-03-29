// 文件上传相关的JavaScript代码
document.addEventListener('DOMContentLoaded', function() {
    // 获取文件输入元素
    const certFileInput = document.getElementById('cert-file');
    const keyFileInput = document.getElementById('key-file');
    
    // 获取文件名显示元素
    const certFilename = document.getElementById('cert-filename');
    const keyFilename = document.getElementById('key-filename');
    
    // 获取上传按钮
    const uploadButtons = document.querySelectorAll('.upload-btn');
    
    // 获取验证按钮和结果显示区域
    const verifyBtn = document.getElementById('verify-btn');
    const verifyResult = document.getElementById('verify-result');
    const verifyMessage = document.getElementById('verify-message');
    const verifyUrl = document.getElementById('verify-url');
    
    // 获取证书类型单选按钮
    const certTypeRadios = document.querySelectorAll('input[name="cert-type"]');
    
    // 创建证书列表选择框的容器
    const certListContainer = document.createElement('div');
    certListContainer.style.position = 'relative';
    document.querySelector('.radio-group').insertAdjacentElement('afterend', certListContainer);

    // 创建证书列表选择框
    const certListSelect = document.createElement('select');
    certListSelect.id = 'cert-list';
    certListSelect.className = 'form-control';
    certListSelect.style.position = 'absolute';
    certListSelect.style.display = 'none';
    certListSelect.style.left = '50px';
    certListSelect.style.top = '0';
    certListSelect.style.width = '181.6px';
    certListSelect.style.height = '31.6px';
    certListSelect.style.zIndex = '1';
    certListContainer.appendChild(certListSelect);
    
    // 加载证书列表
    function loadCertOptions() {
        $.ajax({
            url: '/list_certs',
            type: 'GET',
            headers: {
                'Accept': 'application/json'
            },
            success: function(response) {
                certListSelect.innerHTML = '<option value="">请选择证书</option>';
                if (response && Array.isArray(response.certs)) {
                    response.certs.forEach(cert => {
                        if (cert && cert.name) {
                            const option = document.createElement('option');
                            option.value = cert.name;
                            option.textContent = cert.name;
                            certListSelect.appendChild(option);
                        }
                    });
                    if (response.certs.length === 0) {
                        const option = document.createElement('option');
                        option.value = '';
                        option.textContent = '暂无可用证书';
                        option.disabled = true;
                        certListSelect.appendChild(option);
                    }
                } else {
                    console.error('证书列表格式错误');
                    alert('获取证书列表失败：数据格式错误');
                }
            },
            error: function(xhr, status, error) {
                console.error('获取证书列表失败:', error);
                const errorMsg = xhr.responseJSON && xhr.responseJSON.message 
                    ? xhr.responseJSON.message 
                    : '请稍后重试';
                alert('获取证书列表失败：' + errorMsg);
            }
        });
    }
    
    // 证书列表选择事件
    certListSelect.addEventListener('change', function() {
        const selectedCert = this.value;
        if (selectedCert) {
            certFilename.textContent = selectedCert + '.crt';
            keyFilename.textContent = selectedCert + '.key';
        } else {
            certFilename.textContent = '未选择文件';
            keyFilename.textContent = '未选择文件';
        }
    });
    
    // 证书类型切换事件处理
    certTypeRadios.forEach(radio => {
        radio.addEventListener('change', function() {
            if (this.value === 'qilin') {
                // 显示证书列表，隐藏上传按钮
                certListSelect.style.display = 'block';
                loadCertOptions();
                uploadButtons.forEach(button => {
                    button.style.display = 'none';
                });
            } else {
                // 隐藏证书列表，显示上传按钮
                certListSelect.style.display = 'none';
                certListSelect.value = '';
                certFilename.textContent = '未选择文件';
                keyFilename.textContent = '未选择文件';
                uploadButtons.forEach(button => {
                    button.style.display = 'inline-block';
                });
            }
        });
    });

    
    // 初始化时触发一次change事件
    document.querySelector('input[name="cert-type"]:checked').dispatchEvent(new Event('change'));
    
    // 验证按钮点击事件
    if (verifyBtn) {
        verifyBtn.addEventListener('click', function() {
            // 获取用户输入的地址
            const address = document.getElementById('verify-address').value;
            if (!address) {
                alert('请输入IP地址或域名');
                return;
            }
            
            // 获取证书类型
            const certType = document.querySelector('input[name="cert-type"]:checked').value;
            
            // 准备表单数据
            const formData = new FormData();
            formData.append('address', address);
            formData.append('cert_type', certType);
            
            if (certType === 'qilin') {
                // 使用qilin SSL申请的证书
                const selectedCert = certListSelect.value;
                if (!selectedCert) {
                    alert('请选择证书');
                    return;
                }
                formData.append('cert_name', selectedCert);
            } else {
                // 使用上传的自定义证书
                const certFile = certFilename.textContent;
                const keyFile = keyFilename.textContent;
                
                if (certFile === '未选择文件' || keyFile === '未选择文件') {
                    alert('请上传证书和私钥文件');
                    return;
                }
                
                formData.append('cert_filename', certFile);
                formData.append('key_filename', keyFile);
            }
            
            // 显示加载提示
            verifyBtn.disabled = true;
            verifyBtn.textContent = '验证中...请稍后';
            
            // 发送请求到服务器
            fetch('/verify_cert', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                verifyBtn.disabled = false;
                verifyBtn.textContent = '验证';
                
                if (data.success) {
                    // 显示验证结果
                    verifyMessage.textContent = data.message;
                    verifyUrl.textContent = data.verify_url;
                    verifyUrl.href = data.verify_url;
                    verifyResult.style.display = 'block';
                    
                    // 自动打开验证URL
                    window.open(data.verify_url, '_blank');

                    // 添加倒计时功能
                    let countdown = 30;
                    const countdownInterval = setInterval(() => {
                        countdown--;
                        verifyMessage.textContent = `验证服务器已启动，${countdown}秒后将自动关闭`;
                        
                        if (countdown <= 0) {
                            clearInterval(countdownInterval);
                            verifyResult.style.display = 'none';
                        }
                    }, 1000);
                } else {
                    alert('验证失败：' + data.message);
                    verifyResult.style.display = 'none';
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('验证请求失败，请稍后重试');
                verifyBtn.disabled = false;
                verifyBtn.textContent = '验证';
            });
        });
    }
    
    // 证书文件选择处理
    certFileInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            // 创建FormData对象
            const formData = new FormData();
            formData.append('file', file);
            
            // 发送文件到服务器
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    certFilename.textContent = file.name;
                    certFilename.title = file.name;
                } else {
                    alert('文件上传失败：' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('文件上传失败');
            });
        }
    });
    
    // 私钥文件选择处理
    keyFileInput.addEventListener('change', function(e) {
        const file = e.target.files[0];
        if (file) {
            // 创建FormData对象
            const formData = new FormData();
            formData.append('file', file);
            
            // 发送文件到服务器
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                if (data.success) {
                    keyFilename.textContent = file.name;
                    keyFilename.title = file.name;
                } else {
                    alert('文件上传失败：' + data.message);
                }
            })
            .catch(error => {
                console.error('Error:', error);
                alert('文件上传失败');
            });
        }
    });
});
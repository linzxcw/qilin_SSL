// 证书列表加载脚本
$(document).ready(function() {
    // 页面加载完成后，获取证书列表
    loadCertList();

    // 全选/取消全选复选框事件
    $("#select-all-certs").change(function() {
        $(".cert-checkbox").prop("checked", $(this).prop("checked"));
    });

    // 单个复选框改变事件
    $(document).on("change", ".cert-checkbox", function() {
        var allChecked = $(".cert-checkbox").length === $(".cert-checkbox:checked").length;
        $("#select-all-certs").prop("checked", allChecked);
    });

    // 删除证书按钮点击事件
    $("#delete-cert-btn").click(function() {
        var selectedCerts = $(".cert-checkbox:checked").map(function() {
            return $(this).data("cert-name");
        }).get();

        if (selectedCerts.length === 0) {
            alert("请选择要删除的证书");
            return;
        }

        // 显示删除确认模态窗口
        $("#delete-cert-modal").show();

        // 确认删除按钮点击事件
        $("#confirm-delete-cert-btn").off("click").on("click", function() {
            $.ajax({
                url: "/delete_certs",
                type: "POST",
                contentType: "application/json",
                data: JSON.stringify({ cert_names: selectedCerts }),
                success: function(response) {
                    // 取消全选复选框的选中状态
                    $("#select-all-certs").prop("checked", false);
                    // 关闭模态窗口
                    $("#delete-cert-modal").hide();
                    
                    // 删除成功后直接刷新证书列表
                    if (response.status === 'success') {
                        loadCertList();
                    } else {
                        alert('删除失败');
                    }
                },
                error: function(xhr) {
                    try {
                        var response = JSON.parse(xhr.responseText);
                        alert(response.message || '删除证书失败，请稍后重试');
                    } catch (e) {
                        alert('删除证书失败，请稍后重试');
                    }
                    // 关闭模态窗口
                    $("#delete-cert-modal").hide();
                }
            });
        });

        // 取消删除按钮点击事件
        $("#cancel-delete-cert-btn, #delete-cert-modal .close").off("click").on("click", function() {
            $("#delete-cert-modal").hide();
        });
    });
});

// 加载证书列表函数
function loadCertList(page = 1) {
    $.ajax({
        url: "/list_certs",
        type: "GET",
        data: { page: page },
        success: function(response) {
            // 如果返回的不是空字符串，则更新证书表格内容
            if (response.trim() !== "") {
                $(".data-table:eq(1) tbody").html(response);
                
                // 绑定分页链接点击事件
                $(".page-link").click(function(e) {
                    e.preventDefault();
                    var pageNum = $(this).data("page");
                    loadCertList(pageNum);
                });
            }
        },
        error: function(xhr) {
            console.error("获取证书列表失败:", xhr.responseText);
        }
    });
}
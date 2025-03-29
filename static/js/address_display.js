document.addEventListener('DOMContentLoaded', function() {
    // 处理所有地址列表
    const allAddressLists = document.querySelectorAll('.address-list');
    
    // 遍历所有地址列表，为符合条件的添加has-more类和collapsed类
    allAddressLists.forEach(list => {
        const items = list.querySelectorAll('li');
        
        if (items.length > 3) {
            list.classList.add('has-more');
            list.classList.add('collapsed');
        }
    });
    
    // 设置显示的最大行数，超过这个数量会显示省略号
    const MAX_VISIBLE_ITEMS = 3;
    
    // 为所有地址列表添加鼠标悬停事件
    document.querySelectorAll('.address-list').forEach(list => {
        const items = list.querySelectorAll('li');
        
        if (items.length > MAX_VISIBLE_ITEMS) {
            // 默认收起内容
            list.classList.add('collapsed');
            
            // 添加鼠标悬停事件
            list.parentNode.addEventListener('mouseenter', function() {
                list.classList.remove('collapsed');
            });
            
            list.parentNode.addEventListener('mouseleave', function() {
                list.classList.add('collapsed');
            });
        }
    });
});
// Draw directly at sprite resolution so the scene keeps its pixel edges at any size.
(() => {
    const ctx = document.querySelector("#window-seat")?.getContext("2d");
    if (!ctx) return;

    function rect(x, y, w, h, color) {
        ctx.fillStyle = color;
        ctx.fillRect(x, y, w, h);
    }

    // Charcoal window frame with a blue-gray sky and a few lights still on across the street.
    const wood = "#525252";
    const edge = "#878d96";
    rect(47, 8, 147, 106, "#212121");
    rect(44, 5, 148, 106, wood);
    rect(45, 5, 146, 2, edge);
    rect(48, 9, 140, 98, "#121619");
    const sky = ["#21272a", "#2b3236", "#343a3f", "#444c53", "#525d65"];
    sky.forEach((color, i) => rect(50, 11 + 18 * i, 136, 18, color));
    const stars = [[57,26],[70,17],[79,34],[100,45],[127,21],[136,35],[149,17],[162,39],[179,24],[171,53],[63,51],[91,56],[146,50]];
    stars.forEach(([x,y], i) => rect(x, y, i % 4 === 0 ? 2 : 1, 1, "#c1c7cd"));
    const moon = "#f2e3bf";
    rect(96,17,5,2,moon); rect(93,19,5,2,moon); rect(91,21,5,7,moon);
    rect(93,28,6,3,moon); rect(96,31,9,2,moon); rect(101,29,6,2,moon);
    rect(105,27,3,2,moon);
    const skyline = [[50,78,11],[61,69,12],[73,74,9],[82,61,16],[98,70,13],[111,65,9],[120,80,15],[135,71,17],[152,58,12],[164,66,15],[179,75,7]];
    skyline.forEach(([x,y,w]) => {
        rect(x, y, w, 107-y, "#343a3f");
        if (w > 10) rect(x+3, y-3, w-6, 3, "#343a3f");
        for (let wy = y+5; wy < 99; wy += 7) {
            for (let wx = x+3; wx < x+w-2; wx += 5) {
                if ((wx + wy) % 4 === 0) rect(wx,wy,2,2,"#c6b99e");
            }
        }
    });
    rect(50,94,26,13,"#262626"); rect(55,89,11,6,"#262626");
    rect(76,99,34,8,"#262626"); rect(157,88,29,19,"#262626");
    rect(50,64,136,3,wood); rect(50,64,136,1,edge);
    rect(115,10,4,97,wood); rect(115,10,1,97,edge);
    rect(41,107,154,3,edge); rect(38,110,162,5,wood);

    // Broad leaves silhouetted against the window.
    const stem = "#878d96";
    const leaf = "#89958c";
    rect(180,80,2,23,stem); rect(174,88,7,2,stem); rect(183,83,6,2,stem);
    rect(168,81,6,3,leaf); rect(171,84,6,4,leaf);
    rect(178,72,3,7,leaf); rect(180,76,3,7,leaf);
    rect(188,75,7,4,leaf); rect(185,79,7,4,leaf);
    rect(187,89,8,3,leaf); rect(183,92,6,2,leaf);
    rect(173,98,17,3,"#adb1b3"); rect(175,101,13,7,"#777d80");
    rect(177,101,2,5,"#91979a");

    // Lamplight on a desk, a pair of paperbacks, and a curled-up tabby.
    rect(15,118,207,3,"#a8a8a8"); rect(18,121,201,5,"#6f6f6f");
    rect(23,126,190,3,"#393939"); rect(29,129,5,6,"#323232"); rect(204,129,5,6,"#323232");
    rect(42,113,67,5,"#52606d"); rect(44,114,61,2,"#a8a8a8");
    rect(46,108,67,5,"#697077"); rect(48,109,62,2,"#c1c7cd");
    const fur = "#a8a8a8";
    const light = "#c6c6c6";
    const stripe = "#767676";
    rect(71,104,36,4,stripe); rect(74,97,37,8,fur); rect(78,93,28,5,fur);
    rect(83,91,17,3,light); rect(80,94,23,2,light); rect(108,99,5,6,stripe);
    rect(82,94,3,5,stripe); rect(88,93,3,5,stripe); rect(94,93,3,4,stripe);
    rect(59,97,19,9,light); rect(58,94,4,7,light); rect(60,96,5,4,light);
    rect(72,94,4,6,light); rect(69,96,4,3,light); rect(60,105,16,3,fur);
    rect(61,102,4,1,"#393939"); rect(69,102,4,1,"#393939"); rect(65,104,2,1,stripe);
    rect(93,104,18,3,stripe); rect(88,106,18,2,stripe); rect(86,105,7,2,light);

    // Tea, with a broken pixel line for the steam.
    rect(142,107,15,9,"#a2a9b0"); rect(144,116,11,2,"#697077");
    rect(143,106,13,2,"#dde1e6"); rect(145,106,9,1,"#343a3f");
    rect(157,108,4,2,"#a2a9b0"); rect(160,110,2,3,"#a2a9b0"); rect(157,113,4,2,"#a2a9b0");
    rect(146,110,2,4,"#c1c7cd"); rect(149,100,1,3,"#a2a9b0"); rect(147,97,2,3,"#878d96");
    rect(148,94,1,2,"#697077");
})();

// Draw directly at sprite resolution so the scene keeps its pixel edges at any size.
(() => {
    const ctx = document.querySelector("#window-seat")?.getContext("2d");
    if (!ctx) return;

    function rect(x, y, w, h, color) {
        ctx.fillStyle = color;
        ctx.fillRect(x, y, w, h);
    }

    // Rosewood window with a violet sky and a few lights still on across the street.
    const wood = "#644452";
    const edge = "#956877";
    rect(47, 8, 147, 106, "#2d2330");
    rect(44, 5, 148, 106, wood);
    rect(45, 5, 146, 2, edge);
    rect(48, 9, 140, 98, "#282235");
    const sky = ["#39304e", "#4c385c", "#644469", "#805172", "#996679"];
    sky.forEach((color, i) => rect(50, 11 + 18 * i, 136, 18, color));
    const stars = [[57,26],[70,17],[79,34],[100,45],[127,21],[136,35],[149,17],[162,39],[179,24],[171,53],[63,51],[91,56],[146,50]];
    stars.forEach(([x,y], i) => rect(x, y, i % 4 === 0 ? 2 : 1, 1, "#dbc0c2"));
    const moon = "#ffdbb2";
    rect(96,17,5,2,moon); rect(93,19,5,2,moon); rect(91,21,5,7,moon);
    rect(93,28,6,3,moon); rect(96,31,9,2,moon); rect(101,29,6,2,moon);
    rect(105,27,3,2,moon);
    const skyline = [[50,78,11],[61,69,12],[73,74,9],[82,61,16],[98,70,13],[111,65,9],[120,80,15],[135,71,17],[152,58,12],[164,66,15],[179,75,7]];
    skyline.forEach(([x,y,w]) => {
        rect(x, y, w, 107-y, "#4a384b");
        if (w > 10) rect(x+3, y-3, w-6, 3, "#4a384b");
        for (let wy = y+5; wy < 99; wy += 7) {
            for (let wx = x+3; wx < x+w-2; wx += 5) {
                if ((wx + wy) % 4 === 0) rect(wx,wy,2,2,"#f3b59b");
            }
        }
    });
    rect(50,94,26,13,"#362a39"); rect(55,89,11,6,"#362a39");
    rect(76,99,34,8,"#362a39"); rect(157,88,29,19,"#362a39");
    rect(50,64,136,3,wood); rect(50,64,136,1,edge);
    rect(115,10,4,97,wood); rect(115,10,1,97,edge);
    rect(41,107,154,3,edge); rect(38,110,162,5,wood);

    // Broad leaves silhouetted against the window.
    const stem = "#9a777e";
    const leaf = "#8baa9e";
    rect(180,80,2,23,stem); rect(174,88,7,2,stem); rect(183,83,6,2,stem);
    rect(168,81,6,3,leaf); rect(171,84,6,4,leaf);
    rect(178,72,3,7,leaf); rect(180,76,3,7,leaf);
    rect(188,75,7,4,leaf); rect(185,79,7,4,leaf);
    rect(187,89,8,3,leaf); rect(183,92,6,2,leaf);
    rect(173,98,17,3,"#d9a08e"); rect(175,101,13,7,"#ad7477");
    rect(177,101,2,5,"#c18c86");

    // Lamplight on a desk, a pair of paperbacks, and a curled-up tabby.
    rect(15,118,207,3,"#be8c89"); rect(18,121,201,5,"#885e69");
    rect(23,126,190,3,"#543d49"); rect(29,129,5,6,"#44313d"); rect(204,129,5,6,"#44313d");
    rect(42,113,67,5,"#915f74"); rect(44,114,61,2,"#c39a96");
    rect(46,108,67,5,"#6c6578"); rect(48,109,62,2,"#c7aba4");
    const fur = "#bf8485";
    const light = "#e0a396";
    const stripe = "#976670";
    rect(71,104,36,4,stripe); rect(74,97,37,8,fur); rect(78,93,28,5,fur);
    rect(83,91,17,3,light); rect(80,94,23,2,light); rect(108,99,5,6,stripe);
    rect(82,94,3,5,stripe); rect(88,93,3,5,stripe); rect(94,93,3,4,stripe);
    rect(59,97,19,9,light); rect(58,94,4,7,light); rect(60,96,5,4,light);
    rect(72,94,4,6,light); rect(69,96,4,3,light); rect(60,105,16,3,fur);
    rect(61,102,4,1,"#583c4b"); rect(69,102,4,1,"#583c4b"); rect(65,104,2,1,stripe);
    rect(93,104,18,3,stripe); rect(88,106,18,2,stripe); rect(86,105,7,2,light);

    // Tea, with a broken pixel line for the steam.
    rect(142,107,15,9,"#d59094"); rect(144,116,11,2,"#b77580");
    rect(143,106,13,2,"#efc1ab"); rect(145,106,9,1,"#684250");
    rect(157,108,4,2,"#cf8c90"); rect(160,110,2,3,"#cf8c90"); rect(157,113,4,2,"#cf8c90");
    rect(146,110,2,4,"#e9b0a0"); rect(149,100,1,3,"#c9a6a9"); rect(147,97,2,3,"#b396a0");
    rect(148,94,1,2,"#a28e9c");
})();

/*
Copyright 2020 The Matrix.org Foundation C.I.C.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

import {Tree} from "../src/lbbtree";

describe("Left-balanced binary tree", () => {
    it("should iterate all the nodes", () => {
        const tree = new Tree<number>([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
        expect([...tree]).toEqual([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
    });
    it("should iterate a root->leaf path", () => {
        const tree = new Tree<number>([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
        expect([...tree.pathToLeafNum(0)]).toEqual([15, 7, 3, 1, 0]);
        expect([...tree.pathToLeafNum(1)]).toEqual([15, 7, 3, 1, 2]);
        expect([...tree.pathToLeafNum(2)]).toEqual([15, 7, 3, 5, 4]);
        expect([...tree.pathToLeafNum(3)]).toEqual([15, 7, 3, 5, 6]);
        expect([...tree.pathToLeafNum(4)]).toEqual([15, 7, 11, 9, 8]);
        expect([...tree.pathToLeafNum(5)]).toEqual([15, 7, 11, 9, 10]);
        expect([...tree.pathToLeafNum(6)]).toEqual([15, 7, 11, 13, 12]);
        expect([...tree.pathToLeafNum(7)]).toEqual([15, 7, 11, 13, 14]);
        expect([...tree.pathToLeafNum(8)]).toEqual([15, 23, 19, 17, 16]);
        expect([...tree.pathToLeafNum(9)]).toEqual([15, 23, 19, 17, 18]);
        expect([...tree.pathToLeafNum(10)]).toEqual([15, 23, 19, 21, 20]);
        expect([...tree.pathToLeafNum(11)]).toEqual([15, 23, 19, 21, 22]);
        expect([...tree.pathToLeafNum(12)]).toEqual([15, 23, 25, 24]);
        expect([...tree.pathToLeafNum(13)]).toEqual([15, 23, 25, 26]);
    });
    it("should iterate a co-path", () => {
        const tree = new Tree<number>([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
        expect([...tree.coPathOfLeafNum(0)]).toEqual([23, 11, 5, 2]);
        expect([...tree.coPathOfLeafNum(1)]).toEqual([23, 11, 5, 0]);
        expect([...tree.coPathOfLeafNum(2)]).toEqual([23, 11, 1, 6]);
        expect([...tree.coPathOfLeafNum(3)]).toEqual([23, 11, 1, 4]);
        expect([...tree.coPathOfLeafNum(4)]).toEqual([23, 3, 13, 10]);
        expect([...tree.coPathOfLeafNum(5)]).toEqual([23, 3, 13, 8]);
        expect([...tree.coPathOfLeafNum(6)]).toEqual([23, 3, 9, 14]);
        expect([...tree.coPathOfLeafNum(7)]).toEqual([23, 3, 9, 12]);
        expect([...tree.coPathOfLeafNum(8)]).toEqual([7, 25, 21, 18]);
        expect([...tree.coPathOfLeafNum(9)]).toEqual([7, 25, 21, 16]);
        expect([...tree.coPathOfLeafNum(10)]).toEqual([7, 25, 17, 22]);
        expect([...tree.coPathOfLeafNum(11)]).toEqual([7, 25, 17, 20]);
        expect([...tree.coPathOfLeafNum(12)]).toEqual([7, 19, 26]);
        expect([...tree.coPathOfLeafNum(13)]).toEqual([7, 19, 24]);
    });
    it("should replace paths", () => {
        const tree = new Tree<number | string>([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
        expect([...tree.pathToLeafNum(3)]).toEqual([15, 7, 3, 5, 6]);
        const newtree = tree.replacePathToLeaf(3, ["new15", "new7", "new3", "new5", "new6"]);
        expect([...newtree]).toEqual([
            0, 1, 2, "new3", 4, "new5", "new6", "new7", 8, 9, 10, 11, 12, 13, 14, "new15",
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
        // original tree should still be the same
        expect([...tree]).toEqual([
            0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
            16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26,
        ]);
    });
    it("should add nodes", () => {
        const t0 = new Tree<number>([0]);
        function sum(n1, n2) { return n1.data + n2.data; }
        const t1 = t0.addNode(1, sum);
        expect([...t1]).toEqual([0, 1, 1]);
        expect([...t0]).toEqual([0]); // original should be unchanged
        const t2 = t1.addNode(2, sum);
        expect([...t2]).toEqual([0, 1, 1, 3, 2]);
        const t3 = t2.addNode(3, sum);
        expect([...t3]).toEqual([0, 1, 1, 6, 2, 5, 3]);
        const t4 = t3.addNode(4, sum);
        expect([...t4]).toEqual([0, 1, 1, 6, 2, 5, 3, 10, 4]);
        const t5 = t4.addNode(5, sum);
        expect([...t5]).toEqual([0, 1, 1, 6, 2, 5, 3, 15, 4, 9, 5]);
        const t6 = t5.addNode(6, sum);
        expect([...t6]).toEqual([0, 1, 1, 6, 2, 5, 3, 21, 4, 9, 5, 15, 6]);
        const t7 = t6.addNode(7, sum);
        expect([...t7]).toEqual([0, 1, 1, 6, 2, 5, 3, 28, 4, 9, 5, 22, 6, 13, 7]);
    });
});

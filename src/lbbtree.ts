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

/** Left-balanced binary tree
 */

export class Leaf<T> {
    constructor(public readonly data: T) {}
}

export class Internal<T> {
    constructor(
        public readonly data: T,
        public readonly leftChild: Leaf<T> | Internal<T>,
        public readonly rightChild: Leaf<T> | Internal<T>,
    ) {}
}

export type Node<T> = Leaf<T> | Internal<T>;

/** The depth of a tree, given its size
 */
function depth(size: number): number {
    return Math.floor(Math.log2(2*size - 1));
}

/** Basic path iterator from the root of a tree to the leaf.
 */
class PathIterator<Val, Acc> {
    private mask: number;
    constructor(
        private size: number,
        private leafNum: number,
        private transform: (boolean, Acc) => [Val, Acc],
        private acc: Acc,
    ) {
        const d = depth(size);
        this.mask = d > 0 ? 1 << (d-1) : 0;
    }
    next(): {done: boolean; value?: Val} {
        // FIXME: this needs comments
        if (this.mask < 0) {
            return {done: true};
        }
        if (this.mask == 0) {
            const [value, acc] = this.transform(undefined, this.acc);
            this.acc = acc

            if (value != undefined) {
                this.mask = -1;
                return {done: false, value};
            } else {
                return {done: true};
            }
        } else if (this.size && this.leafNum & this.mask) {
            this.size -= this.mask;
            this.leafNum -= this.mask;

            const d = depth(this.size);
            this.mask = d > 0 ? 1 << (d-1) : 0;

            const [value, acc] = this.transform(true, this.acc);
            this.acc = acc;
            return {done: false, value};
        } else {
            const dir = !this.size && !!(this.leafNum & this.mask);
            this.size = 0;
            this.mask >>= 1;

            const [value, acc] = this.transform(dir, this.acc);
            this.acc = acc;
            return {done: false, value};
        }
    }
    [Symbol.iterator]() {
        return new PathIterator(this.size, this.leafNum, this.transform, this.acc);
    }
}

export class Tree<T> {
    readonly size: number; // the number of leaf nodes
    readonly root: Node<T>;
    constructor(data: T[]) {
        const length = data.length;
        if (length % 2 !== 1) {
            throw new Error("Must have an odd number of nodes");
        }
        this.size = (length + 1) / 2;
        this.root = this.partialTree(data, 0, length);
    }

    pathToLeafNum(leafNum: number): PathIterator<T, Node<T>> {
        return new PathIterator(
            this.size, leafNum,
            (dir: boolean | undefined, acc: Node<T>) => {
                const val = acc.data;
                if (dir === undefined) {
                    return [val, acc];
                } else if (dir) {
                    const next = (acc as Internal).rightChild;
                    return [val, next];
                } else {
                    const next = (acc as Internal).leftChild;
                    return [val, next];
                }
            },
            this.root,
        );
    }

    coPathOfLeafNum(leafNum: number): PathIterator<T, Node<T>> {
        return new PathIterator(
            this.size, leafNum,
            (dir: boolean | undefined, acc: Node<T>) => {
                if (dir === undefined) {
                    return [undefined, acc];
                } else if (dir) {
                    const val = (acc as Internal).leftChild.data;
                    const next = (acc as Internal).rightChild;
                    return [val, next];
                } else {
                    const val = (acc as Internal).rightChild.data;
                    const next = (acc as Internal).leftChild;
                    return [val, next];
                }
            },
            this.root,
        );
    }

    // build a (possibly) partial tree from an array of data
    private partialTree(data: T[], start: number, finish: number): Node<T> {
        const numNodes = finish - start;
        if (numNodes == 1) {
            return new Leaf<T>(data[start]);
        }
        if (numNodes < 0) {
            throw new Error("Something broke");
        }

        const numLeaves = (numNodes + 1) / 2;
        const d = depth(numLeaves);
        const numLeftTreeLeaves = 1 << (d-1);
        const numLeftTreeNodes = 2*numLeftTreeLeaves - 1;

        const leftChild: Node<T> = this.completeTree(
            data, start, start + numLeftTreeNodes,
        );
        const rightChild: Node<T> = this.partialTree(
            data, start + numLeftTreeNodes + 1, finish,
        );
        return new Internal<T>(data[start+numLeftTreeNodes], leftChild, rightChild);
    }
    // build a complete tree from an array of data
    private completeTree(data: T[], start: number, finish: number): Node<T> {
        const numNodes = finish - start;
        if (numNodes == 1) {
            return new Leaf<T>(data[start])
        }

        const subTreeSize = (numNodes - 1) >> 1;

        const leftChild: Node<T> = this.completeTree(
            data, start, start + subTreeSize,
        );
        const rightChild: Node<T> = this.completeTree(
            data, start + subTreeSize + 1, finish,
        );
        return new Internal<T>(data[start+subTreeSize], leftChild, rightChild);
    }
}
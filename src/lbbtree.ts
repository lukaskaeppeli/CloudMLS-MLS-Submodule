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

/** Left-balanced binary tree, implemented using an immutable tree structure.
 * Operations that modify the tree return a new tree, leaving the original tree
 * unchanged.
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
        private transform: (dir: boolean, acc: Acc) => [Val, Acc],
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
        return new PathIterator<Val, Acc>(this.size, this.leafNum, this.transform, this.acc);
    }
}

class PathDirectionIterator {
    constructor(
        private size: number,
        private leafNum: number,
    ) {}
    [Symbol.iterator]() {
        return new PathIterator<boolean, undefined>(
            this.size, this.leafNum,
            (dir: boolean, acc: undefined) => { return [dir, undefined]; },
            undefined);
    }
}

class NodeIterator<T> {
    private path: Node<T>[];
    private dirs: number[];
    constructor(private root: Node<T>) {
        this.path = [root];
        this.dirs = [];
        this.pushLeftPath(root);
    }
    private pushLeftPath(start: Node<T>): void {
        for (let cur = start; cur instanceof Internal;) {
            cur = cur.leftChild;
            this.path.push(cur);
            this.dirs.push(-1)
        }
    }
    next(): {done: boolean, value?: T} {
        if (this.path.length === 0) {
            // we've iterated through the whole tree
            return {done: true}
        } else if (this.dirs.length === 0) {
            // special cases where the root is a leaf node
            const node = this.path.pop();
            return {done: false, value: node.data};
        }

        const lastdir = this.dirs.pop();
        switch (lastdir) {
            case -1:
            {
                const node = this.path.pop();
                this.dirs.push(0);
                return {done: false, value: node.data};
            }
            case 0:
            {
                const node = this.path[this.path.length - 1];
                this.dirs.push(1);
                const rightChild = (node as Internal<T>).rightChild;
                this.path.push(rightChild);
                this.pushLeftPath(rightChild);
                return {done: false, value: node.data};
            }
            case 1:
            {
                const node = this.path.pop();
                this.path.pop();
                while (this.dirs.length !== 0 && this.dirs.pop() === 1) {
                    this.path.pop();
                }
                if (this.path.length !== 0) {
                    this.dirs.push(0);
                }
                return {done: false, value: node.data};
            }
        }
    }
}

function replaceNodePath<T>(
    node: Node<T>,
    directions: boolean[],
    values: T[],
    fn: (nodeValue: T, value: T) => T,
    offset: number,
) {
    if (offset == values.length - 1) {
        return new Leaf<T>(fn(node.data, values[offset]));
    } else {
        if (!(node instanceof Internal)) {
            throw new Error("Too few values specified");
        } else if (directions[offset]) {
            return new Internal<T>(
                fn(node.data, values[offset]),
                node.leftChild,
                replaceNodePath(node.rightChild, directions, values, fn, offset + 1),
            );
        } else {
            return new Internal<T>(
                fn(node.data, values[offset]),
                replaceNodePath(node.leftChild, directions, values, fn, offset + 1),
                node.rightChild,
            );
        }
    }
}

function addNode<T>(
    node: Node<T>,
    size: number,
    data: T,
    newDataFn?: (leftChild: Node<T>, rightChild: Node<T>) => T,
): Node<T> {
    const d = depth(size)
    if (size === (1 << d)) {
        // node is the root of a full tree, so just create a new intermediate
        // node that's a parent to the old root and the node-to-be-added.
        const rightChild = new Leaf<T>(data);
        return new Internal<T>(newDataFn(node, rightChild), node, rightChild);
    } else {
        // node is not a full tree, so recurse down the right side
        const leftTreeSize = 1 << (d-1);
        const rightChild = addNode<T>(
            (node as Internal<T>).rightChild, size - leftTreeSize, data, newDataFn,
        );
        const leftChild = (node as Internal<T>).leftChild;
        return new Internal<T>(
            newDataFn(leftChild, rightChild),
            leftChild, rightChild,
        );
    }
}

export class Tree<T> {
    readonly size: number; // the number of leaf nodes
    readonly root: Node<T>;
    constructor(data: T[] | [number, Node<T>]) {
        if (data.length === 2 &&
            typeof(data[0]) === "number" &&
            (data[1] instanceof Internal || data[1] instanceof Leaf)) {
            this.size = data[0] as number;
            this.root = data[1] as Node<T>;
        } else {
            const length = data.length;
            if (length % 2 !== 1) {
                console.log(data);
                throw new Error("Must have an odd number of nodes");
            }
            this.size = (length + 1) / 2;
            this.root = this.partialTree(data as T[], 0, length);
        }
    }

    [Symbol.iterator]() {
        return new NodeIterator<T>(this.root);
    }

    pathToLeafNum(leafNum: number): PathIterator<T, Node<T>> {
        return new PathIterator(
            this.size, leafNum,
            (dir: boolean | undefined, acc: Node<T>) => {
                const val = acc.data;
                if (dir === undefined) {
                    return [val, acc];
                } else if (dir) {
                    const next = (acc as Internal<T>).rightChild;
                    return [val, next];
                } else {
                    const next = (acc as Internal<T>).leftChild;
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
                    const val = (acc as Internal<T>).leftChild.data;
                    const next = (acc as Internal<T>).rightChild;
                    return [val, next];
                } else {
                    const val = (acc as Internal<T>).rightChild.data;
                    const next = (acc as Internal<T>).leftChild;
                    return [val, next];
                }
            },
            this.root,
        );
    }

    replacePathToLeaf(
        leafNum: number, values: T[],
        transform?: (nodeValue: T, value: T) => T,
    ): Tree<T> {
        return new Tree<T>([
            this.size,
            replaceNodePath<T>(
                this.root,
                [...(new PathDirectionIterator(this.size, leafNum))],
                values,
                transform || ((a, b) => b),
                0,
            ),
        ]);
    }

    addNode(
        data: T,
        newDataFn?: (leftChild: Node<T>, rightChild: Node<T>) => T,
    ): Tree<T> {
        return new Tree<T>([
            this.size + 1,
            addNode<T>(this.root, this.size, data, newDataFn),
        ]);
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

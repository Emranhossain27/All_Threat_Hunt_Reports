/**
 * CSIS 3740 — Project 6: File System Simulator (C++)
 * --------------------------------------------------
 * Commands:
 *   pwd
 *   ls [path]
 *   cd <path>
 *   mkdir <path>
 *   touch <path>
 *   write <path> "<content>"
 *   cat <path>
 *   rm <path>
 *   rmdir <path>
 *   du [path]
 *   save
 *   load
 *   help
 *   exit
 *
 * Disk model:
 *   - NUM_BLOCKS = 1024, BLOCK_SIZE = 64 (modifiable)
 *   - File size = content byte length; blocks = ceil(size / BLOCK_SIZE)
 *   - Maintain free-block bitmap; allocate/free on write/overwrite
 *
 * Persistence:
 *   - Save tree and blocks to "disk.txt"
 *   - Simple line-based format (see saveToDisk/loadFromDisk)
 *
 * NOTE: This is a starter skeleton. Implement TODOs. Keep design modular.
 */

#include <bits/stdc++.h>
using namespace std;

static const int NUM_BLOCKS  = 1024;
static const int BLOCK_SIZE  = 64;
static const char* DISK_FILE = "disk.txt";

enum class NodeType { File, Directory };

struct Node {
    string name;
    NodeType type;
    Node* parent = nullptr;
    vector<Node*> children;    // used if Directory
    string data;               // used if File
    vector<int> blocks;        // block indices allocated to this file

    Node(string n, NodeType t, Node* p=nullptr): name(move(n)), type(t), parent(p) {}
};

struct FileSystem {
    Node* root = nullptr;
    Node* cwd  = nullptr;
    vector<bool> freeBlock; // true = free, false = used

    FileSystem() : freeBlock(NUM_BLOCKS, true) {
        root = new Node("/", NodeType::Directory, nullptr);
        cwd  = root;
    }

    ~FileSystem() {
        destroy(root);
    }

    void destroy(Node* n) {
        if (!n) return;
        for (auto* ch : n->children) destroy(ch);
        delete n;
    }

    // ---------- Path helpers ----------
    vector<string> splitPath(const string& path) {
        vector<string> parts;
        string cur;
        for (char c : path) {
            if (c=='/') {
                if (!cur.empty()) { parts.push_back(cur); cur.clear(); }
            } else {
                cur.push_back(c);
            }
        }
        if (!cur.empty()) parts.push_back(cur);
        return parts;
    }

    string formatPath(Node* n) {
        if (n==root) return "/";
        vector<string> segs;
        while (n && n!=root) { segs.push_back(n->name); n=n->parent; }
        reverse(segs.begin(), segs.end());
        string out="/";
        for (size_t i=0;i<segs.size();++i) {
            out += segs[i];
            if (i+1<segs.size()) out += "/";
        }
        return out;
    }

    Node* findChild(Node* dir, const string& name) {
        if (!dir || dir->type!=NodeType::Directory) return nullptr;
        for (auto* ch : dir->children) if (ch->name==name) return ch;
        return nullptr;
    }

    Node* resolvePath(const string& path, bool createDirs=false, bool lastAsDir=false) {
        // Supports absolute (/a/b) and relative (../b). If createDirs, creates missing nodes (dirs only).
        Node* cur = (path.size()>0 && path[0]=='/') ? root : cwd;
        auto parts = splitPath(path);
        for (size_t i=0;i<parts.size();++i) {
            const string& seg = parts[i];
            if (seg=="." || seg.empty()) continue;
            if (seg=="..") { if (cur->parent) cur=cur->parent; continue; }
            Node* child = findChild(cur, seg);
            bool isLast = (i+1==parts.size());
            if (!child) {
                if (createDirs && (!isLast || lastAsDir)) {
                    // make dir
                    Node* nd = new Node(seg, NodeType::Directory, cur);
                    cur->children.push_back(nd);
                    cur = nd;
                } else {
                    return nullptr;
                }
            } else {
                cur = child;
            }
        }
        return cur;
    }

    // ---------- Block management ----------
    int freeBlocks() const {
        return (int)count(freeBlock.begin(), freeBlock.end(), true);
    }

    vector<int> allocBlocks(size_t bytes) {
        int need = (int)((bytes + BLOCK_SIZE - 1) / BLOCK_SIZE);
        if (need==0) return {};
        if (need > freeBlocks()) return {}; // fail
        vector<int> result;
        for (int i=0;i<NUM_BLOCKS && (int)result.size()<need; ++i) {
            if (freeBlock[i]) {
                freeBlock[i] = false;
                result.push_back(i);
            }
        }
        return result;
    }

    void freeBlocksVec(const vector<int>& v) {
        for (int idx : v) {
            if (0<=idx && idx<NUM_BLOCKS) freeBlock[idx] = true;
        }
    }

    // ---------- Commands ----------
    void cmd_pwd() {
        cout << formatPath(cwd) << "\n";
    }

    void cmd_ls(const string& p="") {
        Node* t = p.empty() ? cwd : resolvePath(p);
        if (!t) { cout << "ls: path not found\n"; return; }
        if (t->type==NodeType::File) {
            cout << "[file] " << t->name << " (" << t->data.size() << " bytes)\n";
            return;
        }
        for (auto* ch : t->children) {
            cout << (ch->type==NodeType::Directory ? "[dir]  " : "[file] ")
                 << ch->name;
            if (ch->type==NodeType::File)
                cout << " (" << ch->data.size() << " bytes, blocks=" << ch->blocks.size() << ")";
            cout << "\n";
        }
    }

    void cmd_cd(const string& p) {
        Node* t = resolvePath(p);
        if (!t) { cout << "cd: path not found\n"; return; }
        if (t->type!=NodeType::Directory) { cout << "cd: not a directory\n"; return; }
        cwd = t;
    }

    void cmd_mkdir(const string& p) {
        // create leaf directory
        if (p=="/") { cout << "mkdir: already exists\n"; return; }
        Node* parent = nullptr;
        string name;
        auto pos = p.find_last_of('/');
        if (pos==string::npos) { parent=cwd; name=p; }
        else {
            string parentPath = (pos==0)?"/":p.substr(0,pos);
            name = p.substr(pos+1);
            parent = resolvePath(parentPath);
        }
        if (!parent || parent->type!=NodeType::Directory) { cout<<"mkdir: invalid path\n"; return; }
        if (name.empty()) { cout<<"mkdir: invalid name\n"; return; }
        if (findChild(parent, name)) { cout<<"mkdir: already exists\n"; return; }
        parent->children.push_back(new Node(name, NodeType::Directory, parent));
    }

    void cmd_touch(const string& p) {
        Node* parent = nullptr;
        string name;
        auto pos = p.find_last_of('/');
        if (pos==string::npos) { parent=cwd; name=p; }
        else {
            string parentPath = (pos==0)?"/":p.substr(0,pos);
            name = p.substr(pos+1);
            parent = resolvePath(parentPath);
        }
        if (!parent || parent->type!=NodeType::Directory) { cout<<"touch: invalid path\n"; return; }
        if (name.empty()) { cout<<"touch: invalid name\n"; return; }
        if (findChild(parent, name)) { cout<<"touch: already exists\n"; return; }
        parent->children.push_back(new Node(name, NodeType::File, parent));
    }

    void cmd_write(const string& p, const string& content) {
        Node* t = resolvePath(p);
        if (!t) { 
            // create file at path
            cmd_touch(p);
            t = resolvePath(p);
            if (!t) { cout<<"write: cannot create\n"; return; }
        }
        if (t->type!=NodeType::File) { cout<<"write: not a file\n"; return; }
        // free old blocks
        freeBlocksVec(t->blocks);
        t->blocks.clear();
        // set data and alloc
        t->data = content;
        auto newBlocks = allocBlocks(t->data.size());
        if ((int)newBlocks.size() * BLOCK_SIZE < (int)t->data.size()) {
            // allocation failed; rollback
            cout << "write: insufficient disk space\n";
            t->data.clear();
            return;
        }
        t->blocks = move(newBlocks);
    }

    void cmd_cat(const string& p) {
        Node* t = resolvePath(p);
        if (!t || t->type!=NodeType::File) { cout<<"cat: file not found\n"; return; }
        cout << t->data << "\n";
    }

    bool removeNode(Node* parent, const string& name) {
        for (size_t i=0;i<parent->children.size();++i) {
            Node* ch = parent->children[i];
            if (ch->name==name) {
                if (ch->type==NodeType::Directory && !ch->children.empty()) {
                    return false; // must be empty
                }
                if (ch->type==NodeType::File) freeBlocksVec(ch->blocks);
                parent->children.erase(parent->children.begin()+i);
                // delete subtree
                ch->children.clear();
                delete ch;
                return true;
            }
        }
        return false;
    }

    void cmd_rm(const string& p) {
        Node* parent=nullptr; string name;
        auto pos = p.find_last_of('/');
        if (pos==string::npos) { parent=cwd; name=p; }
        else {
            string parentPath = (pos==0)?"/":p.substr(0,pos);
            name = p.substr(pos+1);
            parent = resolvePath(parentPath);
        }
        if (!parent || parent->type!=NodeType::Directory) { cout<<"rm: invalid path\n"; return; }
        Node* t = findChild(parent, name);
        if (!t || t->type!=NodeType::File) { cout<<"rm: file not found\n"; return; }
        removeNode(parent, name) ? void(cout<<"removed\n") : void(cout<<"rm: failed\n");
    }

    void cmd_rmdir(const string& p) {
        Node* parent=nullptr; string name;
        auto pos = p.find_last_of('/');
        if (pos==string::npos) { parent=cwd; name=p; }
        else {
            string parentPath = (pos==0)?"/":p.substr(0,pos);
            name = p.substr(pos+1);
            parent = resolvePath(parentPath);
        }
        if (!parent || parent->type!=NodeType::Directory) { cout<<"rmdir: invalid path\n"; return; }
        Node* t = findChild(parent, name);
        if (!t || t->type!=NodeType::Directory) { cout<<"rmdir: directory not found\n"; return; }
        if (!t->children.empty()) { cout<<"rmdir: directory not empty\n"; return; }
        removeNode(parent, name) ? void(cout<<"removed\n") : void(cout<<"rmdir: failed\n");
    }

    pair<size_t,size_t> duNode(Node* n) {
        if (!n) return {0,0};
        if (n->type==NodeType::File) {
            size_t bytes = n->data.size();
            size_t blocks = n->blocks.size();
            return {bytes, blocks};
        } else {
            size_t b=0, bl=0;
            for (auto* ch : n->children) {
                auto [cb, cbl] = duNode(ch);
                b += cb; bl += cbl;
            }
            return {b, bl};
        }
    }

    void cmd_du(const string& p="") {
        Node* t = p.empty()? cwd : resolvePath(p);
        if (!t) { cout<<"du: path not found\n"; return; }
        auto [bytes, blocks] = duNode(t);
        cout << "bytes=" << bytes << ", blocks=" << blocks
             << " (block_size=" << BLOCK_SIZE << ")\n";
    }

    // ---------- Persistence ----------
    // Simple text format:
    // First line: NUM_BLOCKS BLOCK_SIZE
    // Next line: FREE_BITMAP as 0/1 string
    // Then one node per line: TYPE PATH SIZE BLOCKS [DATA...]
    //   TYPE: D or F
    //   PATH: absolute (e.g., /, /docs, /docs/readme.txt)
    //   SIZE: file bytes (0 for dirs)
    //   BLOCKS: comma-separated indices for files (or -)
    //   DATA: for files, after a tab, raw content (may contain spaces)
    //
    // NOTE: This is a simple starter; feel free to change to a safer encoding.
    void saveToDisk() {
        ofstream out(DISK_FILE);
        if (!out) { cout<<"save: cannot open disk.txt\n"; return; }
        out << NUM_BLOCKS << " " << BLOCK_SIZE << "\n";
        for (bool f : freeBlock) out << (f?'1':'0');
        out << "\n";
        // BFS traversal
        queue<Node*> q; q.push(root);
        while (!q.empty()) {
            Node* n = q.front(); q.pop();
            for (auto* ch : n->children) q.push(ch);
            string type = (n==root||n->type==NodeType::Directory) ? "D" : "F";
            string path = formatPath(n);
            size_t size = (n->type==NodeType::File) ? n->data.size() : 0;
            string blocksStr = "-";
            if (n->type==NodeType::File && !n->blocks.empty()) {
                blocksStr.clear();
                for (size_t i=0;i<n->blocks.size();++i) {
                    if (i) blocksStr.push_back(',');
                    blocksStr += to_string(n->blocks[i]);
                }
            }
            out << type << " " << path << " " << size << " " << blocksStr;
            if (n->type==NodeType::File && !n->data.empty()) {
                out << "\t" << n->data;
            }
            out << "\n";
        }
        cout<<"Saved to " << DISK_FILE << "\n";
    }

    void clearFS() {
        destroy(root);
        root = new Node("/", NodeType::Directory, nullptr);
        cwd  = root;
        freeBlock.assign(NUM_BLOCKS, true);
    }

    void loadFromDisk() {
        ifstream in(DISK_FILE);
        if (!in) { cout<<"load: cannot open disk.txt\n"; return; }
        clearFS();

        int nb, bs;
        if (!(in >> nb >> bs)) { cout<<"load: header error\n"; return; }
        string bitmap;
        in >> bitmap;
        if ((int)bitmap.size()!=NUM_BLOCKS) {
            // tolerate different sizes by clamping
            for (size_t i=0;i<freeBlock.size() && i<bitmap.size(); ++i)
                freeBlock[i] = (bitmap[i]=='1');
        } else {
            for (int i=0;i<NUM_BLOCKS; ++i) freeBlock[i] = (bitmap[i]=='1');
        }
        string line;
        getline(in, line); // consume eol
        // Recreate nodes
        unordered_map<string, Node*> pathMap;
        pathMap["/"] = root;
        while (getline(in, line)) {
            if (line.empty()) continue;
            // parse: TYPE PATH SIZE BLOCKS [\t DATA]
            // split by tab first
            string meta, data;
            size_t tab = line.find('\t');
            if (tab==string::npos) meta = line;
            else { meta = line.substr(0,tab); data = line.substr(tab+1); }

            stringstream ss(meta);
            string type, path, blocksStr;
            size_t size;
            ss >> type >> path >> size >> blocksStr;
            if (path=="/") continue; // root already exists
            // ensure parent dirs
            auto pos = path.find_last_of('/');
            string parentPath = (pos<=0)?"/":path.substr(0,pos);
            string name = path.substr(pos+1);
            Node* parent = nullptr;
            if (pathMap.count(parentPath)) parent = pathMap[parentPath];
            else {
                // create missing dirs along the path
                parent = root;
                auto parts = splitPath(parentPath);
                string cur = "";
                for (auto& seg : parts) {
                    cur += "/"; cur += seg;
                    if (!pathMap.count(cur)) {
                        Node* d = new Node(seg, NodeType::Directory, parent);
                        parent->children.push_back(d);
                        pathMap[cur]=d;
                        parent=d;
                    } else {
                        parent = pathMap[cur];
                    }
                }
            }
            if (type=="D") {
                Node* d = new Node(name, NodeType::Directory, parent);
                parent->children.push_back(d);
                pathMap[path]=d;
            } else { // file
                Node* f = new Node(name, NodeType::File, parent);
                f->data = data; // may be empty
                // parse blocks
                if (blocksStr!="-") {
                    string tmp; stringstream sb(blocksStr);
                    while (getline(sb, tmp, ',')) {
                        if (!tmp.empty()) f->blocks.push_back(stoi(tmp));
                    }
                }
                parent->children.push_back(f);
                pathMap[path]=f;
            }
        }
        cwd = root;
        cout<<"Loaded from " << DISK_FILE << "\n";
    }

    // ---------- REPL ----------
    static string trim(const string& s) {
        size_t i=0,j=s.size();
        while (i<j && isspace((unsigned char)s[i])) ++i;
        while (j>i && isspace((unsigned char)s[j-1])) --j;
        return s.substr(i,j-i);
    }

    void help() {
        cout << "Commands:\n"
             << "  pwd\n"
             << "  ls [path]\n"
             << "  cd <path>\n"
             << "  mkdir <path>\n"
             << "  touch <path>\n"
             << "  write <path> \"content\"\n"
             << "  cat <path>\n"
             << "  rm <path>\n"
             << "  rmdir <path>\n"
             << "  du [path]\n"
             << "  save | load\n"
             << "  help | exit\n";
    }

    void repl() {
        cout << "FS Simulator — block_size="<<BLOCK_SIZE<<", blocks="<<NUM_BLOCKS<<"\n";
        help();
        string line;
        while (true) {
            cout << formatPath(cwd) << "> ";
            if (!getline(cin, line)) break;
            line = trim(line);
            if (line.empty()) continue;
            string cmd; string arg1; string rest;
            {
                stringstream ss(line);
                ss >> cmd;
                getline(ss, rest);
                rest = trim(rest);
            }
            if (cmd=="exit") break;
            else if (cmd=="help") help();
            else if (cmd=="pwd") cmd_pwd();
            else if (cmd=="ls") cmd_ls(rest);
            else if (cmd=="cd") cmd_cd(rest);
            else if (cmd=="mkdir") cmd_mkdir(rest);
            else if (cmd=="touch") cmd_touch(rest);
            else if (cmd=="cat") cmd_cat(rest);
            else if (cmd=="rm") cmd_rm(rest);
            else if (cmd=="rmdir") cmd_rmdir(rest);
            else if (cmd=="du") cmd_du(rest);
            else if (cmd=="save") saveToDisk();
            else if (cmd=="load") loadFromDisk();
            else if (cmd=="write") {
                // expect: write <path> "content with spaces"
                // parse quoted content
                // find first space split
                auto sp = rest.find(' ');
                if (sp==string::npos) { cout<<"write: usage write <path> \"content\"\n"; continue; }
                string p = rest.substr(0, sp);
                string q = trim(rest.substr(sp+1));
                if (q.size()<2 || q.front()!='"' || q.back()!='"') {
                    cout<<"write: content must be in quotes\n"; continue;
                }
                string content = q.substr(1, q.size()-2);
                cmd_write(p, content);
            } else {
                cout << "Unknown: " << cmd << "\n";
            }
        }
    }
};

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    FileSystem fs;
    fs.repl();
    return 0;
}
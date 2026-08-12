#include <bits/stdc++.h>
using namespace std;

struct Node{
    int val, sz;
    uint32_t pri;
    Node *l,*r;
    Node(int v,uint32_t p):val(v),sz(1),pri(p),l(nullptr),r(nullptr){}
};
static int sz(Node* t){ return t?t->sz:0; }
static void pull(Node* t){ if(t) t->sz=1+sz(t->l)+sz(t->r); }

static void split(Node* t,int k,Node*&a,Node*&b){
    if(!t){ a=b=nullptr; return; }
    if(sz(t->l)>=k){
        split(t->l,k,a,t->l);
        b=t; pull(b);
    }else{
        split(t->r,k-sz(t->l)-1,t->r,b);
        a=t; pull(a);
    }
}
static Node* merge(Node*a,Node*b){
    if(!a) return b;
    if(!b) return a;
    if(a->pri>b->pri){
        a->r=merge(a->r,b); pull(a); return a;
    }else{
        b->l=merge(a,b->l); pull(b); return b;
    }
}
static int kth(Node*t,int k){
    int ls=sz(t->l);
    if(k==ls+1) return t->val;
    if(k<=ls) return kth(t->l,k);
    return kth(t->r,k-ls-1);
}
static void inorder(Node*t,vector<int>&v){
    if(!t) return;
    inorder(t->l,v); v.push_back(t->val); inorder(t->r,v);
}
static uint32_t rng32(){
    static uint64_t x=0x9e3779b97f4a7c15ULL;
    x^=x<<7; x^=x>>9; x^=x<<8;
    return (uint32_t)x;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<int>A(N+1);
    for(int i=1;i<=N;i++) cin>>A[i];

    Node* root=nullptr;
    for(int i=1;i<=N;i++){
        int B=i-A[i];
        if(i==1){
            root=new Node(0,rng32());
            continue;
        }

        int oldLast=kth(root,i-1);
        if(B==i){
            root=merge(new Node(0,rng32()),root);
        }else{
            Node *x,*y,*z;
            split(root,B-1,x,y);
            split(y,1,y,z);
            root=merge(x,z);
            root=merge(new Node(0,rng32()),root);
            root=merge(root,new Node(oldLast+1,rng32()));
        }
    }

    vector<int> ans;
    ans.reserve(N);
    inorder(root,ans);
    for(int i=0;i<N;i++){
        if(i) cout<<' ';
        cout<<ans[i];
    }
    cout<<"\n";
    return 0;
}

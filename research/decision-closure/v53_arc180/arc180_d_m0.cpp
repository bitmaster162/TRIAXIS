#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
static const int64 INF = (1LL<<60);

struct AssignMinSeg{
    int n;
    vector<int64> mn, baseMn, tag;
    AssignMinSeg(const vector<int64>&a){ // 1-indexed
        n=(int)a.size()-1;
        mn.assign(4*n+4,INF);
        baseMn.assign(4*n+4,INF);
        tag.assign(4*n+4,INF);
        build(1,1,n,a);
    }
    void build(int p,int l,int r,const vector<int64>&a){
        if(l==r){ baseMn[p]=a[l]; return; }
        int m=(l+r)>>1;
        build(p<<1,l,m,a); build(p<<1|1,m+1,r,a);
        baseMn[p]=min(baseMn[p<<1],baseMn[p<<1|1]);
    }
    void apply(int p,int64 c){ tag[p]=c; mn[p]=baseMn[p]+c; }
    void push(int p){
        if(tag[p]!=INF){
            apply(p<<1,tag[p]); apply(p<<1|1,tag[p]);
            tag[p]=INF;
        }
    }
    void assignRange(int ql,int qr,int64 c){ if(ql<=qr) assignRange(1,1,n,ql,qr,c); }
    void assignRange(int p,int l,int r,int ql,int qr,int64 c){
        if(ql<=l && r<=qr){ apply(p,c); return; }
        push(p);
        int m=(l+r)>>1;
        if(ql<=m) assignRange(p<<1,l,m,ql,qr,c);
        if(m<qr) assignRange(p<<1|1,m+1,r,ql,qr,c);
        mn[p]=min(mn[p<<1],mn[p<<1|1]);
    }
    int64 query(int ql,int qr){ return query(1,1,n,ql,qr); }
    int64 query(int p,int l,int r,int ql,int qr){
        if(ql<=l && r<=qr) return mn[p];
        push(p);
        int m=(l+r)>>1;
        int64 z=INF;
        if(ql<=m) z=min(z,query(p<<1,l,m,ql,qr));
        if(m<qr) z=min(z,query(p<<1|1,m+1,r,ql,qr));
        return z;
    }
};

struct MaxSeg{
    int n;
    vector<pair<int64,int>> st; // max value, negative index to prefer leftmost
    MaxSeg(const vector<int64>&a){
        n=(int)a.size()-1; st.assign(4*n+4,{-1,0});
        build(1,1,n,a);
    }
    void build(int p,int l,int r,const vector<int64>&a){
        if(l==r){ st[p]={a[l],-l}; return; }
        int m=(l+r)>>1;
        build(p<<1,l,m,a); build(p<<1|1,m+1,r,a);
        st[p]=max(st[p<<1],st[p<<1|1]);
    }
    pair<int64,int> query(int ql,int qr){ return query(1,1,n,ql,qr); }
    pair<int64,int> query(int p,int l,int r,int ql,int qr){
        if(ql<=l && r<=qr) return st[p];
        int m=(l+r)>>1;
        pair<int64,int> z={-1,0};
        if(ql<=m) z=max(z,query(p<<1,l,m,ql,qr));
        if(m<qr) z=max(z,query(p<<1|1,m+1,r,ql,qr));
        return z;
    }
};

struct Req{ int a,r,id; };

static vector<int64> solveRight(const vector<int64>&a, vector<Req> reqs, int outN){
    int n=(int)a.size()-1;
    vector<vector<pair<int,int>>> byR(n+1);
    for(auto q:reqs) byR[q.r].push_back({q.a,q.id});
    vector<int> prv(n+1,0), stk;
    for(int r=1;r<=n;r++){
        while(!stk.empty() && a[stk.back()]<a[r]) stk.pop_back();
        prv[r]=stk.empty()?0:stk.back();
        stk.push_back(r);
    }
    AssignMinSeg seg(a);
    vector<int64> out(outN,INF);
    for(int r=1;r<=n;r++){
        if(r>=2){
            int g=prv[r];
            int l=(g==0?1:g);
            seg.assignRange(l,r-1,a[r]);
        }
        for(auto [aa,id]:byR[r]) out[id]=seg.query(aa,r-1);
    }
    return out;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N,Q;
    if(!(cin>>N>>Q)) return 0;
    vector<int64>A(N+1);
    for(int i=1;i<=N;i++) cin>>A[i];
    vector<int>L(Q),R(Q),P(Q);
    vector<int64>M(Q),extra(Q,INF);
    MaxSeg rmq(A);

    vector<Req> rightReq, revReq;
    for(int qi=0;qi<Q;qi++){
        cin>>L[qi]>>R[qi];
        auto z=rmq.query(L[qi],R[qi]);
        M[qi]=z.first;
        P[qi]=-z.second;
        int p=P[qi], l=L[qi], r=R[qi];
        if(l<p && p<r) extra[qi]=min(extra[qi],A[l]+A[r]);
        if(p<=r-2) rightReq.push_back({p+1,r,qi});
        if(p>=l+2){
            int aa=N-p+2;
            int rr=N-l+1;
            revReq.push_back({aa,rr,qi});
        }
    }

    auto rightAns=solveRight(A,rightReq,Q);
    vector<int64> AR(N+1);
    for(int i=1;i<=N;i++) AR[i]=A[N+1-i];
    auto leftAns=solveRight(AR,revReq,Q);

    for(auto q:rightReq) extra[q.id]=min(extra[q.id],rightAns[q.id]);
    for(auto q:revReq) extra[q.id]=min(extra[q.id],leftAns[q.id]);

    for(int qi=0;qi<Q;qi++) cout<<M[qi]+extra[qi]<<"\n";
    return 0;
}

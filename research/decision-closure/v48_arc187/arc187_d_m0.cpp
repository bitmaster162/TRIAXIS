#include <bits/stdc++.h>
using namespace std;
using int64 = long long;
static const int64 NEG = -(1LL<<60);
static const int64 INF = (1LL<<62);

struct FenwickMax{
    int n; vector<int64> bit;
    FenwickMax(int n=0):n(n),bit(n+1,NEG){}
    void update(int i,int64 v){
        for(++i;i<=n;i+=i&-i) bit[i]=max(bit[i],v);
    }
    int64 queryCount(int cnt) const{ // maximum on indices [0,cnt)
        int64 r=NEG;
        for(int i=cnt;i>0;i-=i&-i) r=max(r,bit[i]);
        return r;
    }
};

struct SegTree{
    int n;
    vector<int64> mxh,maxx,minq,lazy;
    vector<char> has;
    vector<int64> xs;
    SegTree(const vector<int64>& coord):n((int)coord.size()),mxh(4*n,NEG),maxx(4*n,NEG),
        minq(4*n,INF),lazy(4*n,0),has(4*n,0),xs(coord){}
    void apply(int p,int64 h){
        mxh[p]=h; lazy[p]=h; has[p]=1;
        minq[p]=(maxx[p]==NEG?INF:h-maxx[p]);
    }
    void push(int p){
        if(!has[p]) return;
        apply(p<<1,lazy[p]); apply(p<<1|1,lazy[p]);
        has[p]=0;
    }
    void pull(int p){
        mxh[p]=max(mxh[p<<1],mxh[p<<1|1]);
        maxx[p]=max(maxx[p<<1],maxx[p<<1|1]);
        minq[p]=min(minq[p<<1],minq[p<<1|1]);
    }
    void activate(int idx,int p,int l,int r){
        if(l==r){
            maxx[p]=xs[l];
            minq[p]=mxh[p]-xs[l];
            return;
        }
        push(p);
        int m=(l+r)>>1;
        if(idx<=m) activate(idx,p<<1,l,m);
        else activate(idx,p<<1|1,m+1,r);
        pull(p);
    }
    void activate(int idx){ activate(idx,1,0,n-1); }
    void assignRange(int ql,int qr,int64 h,int p,int l,int r){
        if(ql>r||qr<l) return;
        if(ql<=l&&r<=qr){ apply(p,h); return; }
        push(p);
        int m=(l+r)>>1;
        assignRange(ql,qr,h,p<<1,l,m);
        assignRange(ql,qr,h,p<<1|1,m+1,r);
        pull(p);
    }
    void assignRange(int l,int r,int64 h){ if(l<=r) assignRange(l,r,h,1,0,n-1); }
    int firstGe(int ql,int64 v,int p,int l,int r){
        if(r<ql || mxh[p]<v) return n;
        if(l==r) return l;
        push(p);
        int m=(l+r)>>1;
        int z=firstGe(ql,v,p<<1,l,m);
        if(z!=n) return z;
        return firstGe(ql,v,p<<1|1,m+1,r);
    }
    int firstGe(int ql,int64 v){ if(ql>=n) return n; return firstGe(ql,v,1,0,n-1); }
    pair<int64,int64> query(int ql,int qr,int p,int l,int r){
        if(ql>r||qr<l) return {NEG,INF};
        if(ql<=l&&r<=qr) return {maxx[p],minq[p]};
        push(p);
        int m=(l+r)>>1;
        auto a=query(ql,qr,p<<1,l,m);
        auto b=query(ql,qr,p<<1|1,m+1,r);
        return {max(a.first,b.first),min(a.second,b.second)};
    }
    pair<int64,int64> query(int l,int r){
        if(l>r) return {NEG,INF};
        return query(l,r,1,0,n-1);
    }
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int N;
    if(!(cin>>N)) return 0;
    vector<int64>A(N),B(N),lo(N),hi(N),xs;
    for(auto &x:A) cin>>x;
    for(auto &x:B) cin>>x;
    xs.reserve(N);
    for(int i=0;i<N;i++){
        lo[i]=min(A[i],B[i]);
        hi[i]=max(A[i],B[i]);
        xs.push_back(lo[i]);
    }
    sort(xs.begin(),xs.end());
    xs.erase(unique(xs.begin(),xs.end()),xs.end());
    SegTree st(xs);
    FenwickMax fw((int)xs.size());
    vector<char> active(xs.size(),0);
    int64 amin=INF,bmax=NEG;

    for(int i=0;i<N;i++){
        int p=lower_bound(xs.begin(),xs.end(),lo[i])-xs.begin();
        amin=min(amin,hi[i]);
        bmax=max(bmax,lo[i]);

        if(!active[p]){
            st.activate(p);
            active[p]=1;
        }

        int q=st.firstGe(p+1,hi[i]);
        st.assignRange(p+1,q-1,hi[i]);
        fw.update(p,hi[i]);

        int idxa=int(upper_bound(xs.begin(),xs.end(),amin)-xs.begin())-1;
        int64 ans=INF;
        if(idxa>=0){
            int firstGT=st.firstGe(0,bmax+1);
            int t=min(idxa,firstGT-1);
            if(t>=0){
                auto z=st.query(0,t);
                if(z.first!=NEG) ans=min(ans,bmax-z.first);
            }
            if(t+1<=idxa){
                auto z=st.query(t+1,idxa);
                ans=min(ans,z.second);
            }
        }

        int lessCnt=lower_bound(xs.begin(),xs.end(),amin)-xs.begin();
        int64 hA=fw.queryCount(lessCnt);
        int64 right=max(amin,bmax);
        if(hA!=NEG) right=max(right,hA);
        ans=min(ans,right-amin);

        cout<<ans<<"\n";
    }
    return 0;
}

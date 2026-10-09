#include <bits/stdc++.h>
using namespace std;

static const long long MOD = 998244353;

struct SegTree {
    int n;
    vector<long long> st;
    explicit SegTree(int sz=0){ init(sz); }
    void init(int sz){
        n=1; while(n<sz) n<<=1;
        st.assign(2*n,1);
        for(int i=0;i<sz;i++) st[n+i]=0;
        for(int i=n-1;i>=1;i--) st[i]=st[i<<1]*st[i<<1|1]%MOD;
    }
    void setval(int p,long long v){
        p+=n; st[p]=v%MOD;
        for(p>>=1;p;p>>=1) st[p]=st[p<<1]*st[p<<1|1]%MOD;
    }
    long long all() const { return st[1]; }
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N; long long H;
    cin >> N >> H;
    vector<long long> X(N+1);
    vector<pair<long long,int>> a;
    a.reserve(N);
    for(int i=1;i<=N;i++){
        cin >> X[i];
        a.push_back({X[i],i});
    }
    sort(a.begin(),a.end());

    vector<long long> pow2(N+1,1);
    for(int i=1;i<=N;i++) pow2[i]=pow2[i-1]*2%MOD;

    vector<int> lc(N+1,0), rc(N+1,0), dep(N+1,0), compOf(N+1,-1);
    vector<int> compSize;
    vector<pair<int,long long>> upd(N+1,{-1,0});

    int compCnt=0;
    for(int L=0;L<N;){
        int R=L;
        while(R+1<N && a[R+1].first-a[R].first<=H) ++R;
        int m=R-L+1;
        compSize.push_back(m);

        vector<int> st;
        st.reserve(m);
        for(int k=L;k<=R;k++){
            int cur=a[k].second;
            lc[cur]=rc[cur]=0;
            int last=0;
            while(!st.empty() && st.back()>cur){
                last=st.back();
                st.pop_back();
            }
            if(!st.empty()) rc[st.back()]=cur;
            lc[cur]=last;
            st.push_back(cur);
            compOf[cur]=compCnt;
        }
        int root=st.front();
        vector<int> dfs={root};
        dep[root]=0;
        while(!dfs.empty()){
            int v=dfs.back(); dfs.pop_back();
            if(lc[v]){ dep[lc[v]]=dep[v]+1; dfs.push_back(lc[v]); }
            if(rc[v]){ dep[rc[v]]=dep[v]+1; dfs.push_back(rc[v]); }
        }
        for(int k=L;k<=R;k++){
            int v=a[k].second;
            int ch=(lc[v]!=0)+(rc[v]!=0);
            if(ch<2){
                int e=m-dep[v]-(ch==1 ? 1 : 0);
                upd[v]={compCnt,pow2[e]};
            }
        }
        ++compCnt;
        L=R+1;
    }

    SegTree seg(compCnt);
    vector<long long> cur(compCnt,0), ans(N+1,0);
    long long prev=0;
    for(int t=1;t<=N;t++){
        auto [c,w]=upd[t];
        if(c!=-1){
            cur[c]+=w;
            if(cur[c]>=MOD) cur[c]-=MOD;
            seg.setval(c,cur[c]);
        }
        long long now=seg.all();
        ans[t]=(now-prev+MOD)%MOD;
        prev=now;
    }
    for(int t=1;t<=N;t++){
        if(t>1) cout << ' ';
        cout << ans[t];
    }
    cout << '\n';
    return 0;
}

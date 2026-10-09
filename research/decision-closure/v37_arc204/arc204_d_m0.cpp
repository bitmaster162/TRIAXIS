#include <bits/stdc++.h>
using namespace std;

int N,L,R,T,D;
vector<int> vals, answer, cur;
vector<char> used;

bool dfs(int l,int u,int depth){
    if(depth==D){
        if(l==0 && u==0){ answer=cur; return true; }
        return false;
    }
    int s=T+l+u;
    vector<tuple<int,int,int>> cand;
    for(int i=0;i<D;i++) if(!used[i]){
        int p=vals[i], r=p%s;
        if(r<l){
            int flex=0;
            int ns=s-1;
            for(int j=0;j<D;j++) if(!used[j] && j!=i){
                int rr=vals[j]%ns;
                if(rr<l-1 || rr>=(l-1)+T) ++flex;
            }
            cand.emplace_back(flex,p,0);
        }else if(r>=l+T){
            int flex=0;
            int ns=s-1;
            for(int j=0;j<D;j++) if(!used[j] && j!=i){
                int rr=vals[j]%ns;
                if(rr<l || rr>=l+T) ++flex;
            }
            cand.emplace_back(flex,p,1);
        }
    }
    sort(cand.begin(),cand.end(),[](auto a,auto b){
        if(get<0>(a)!=get<0>(b)) return get<0>(a)>get<0>(b);
        return get<1>(a)>get<1>(b);
    });
    for(auto [flex,p,tp]:cand){
        int idx=p-T;
        if(idx<0||idx>=D||used[idx]) continue;
        used[idx]=1; cur.push_back(p);
        bool ok = tp==0 ? dfs(l-1,u,depth+1) : dfs(l,u-1,depth+1);
        if(ok) return true;
        cur.pop_back(); used[idx]=0;
    }
    return false;
}

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    if(!(cin>>N>>L>>R)) return 0;
    T=R-L;
    D=N-T;
    vals.resize(D);
    iota(vals.begin(),vals.end(),T);
    used.assign(D,0);
    if(dfs(L,N-R,0)){
        cout<<"Yes\n";
        for(int i=0;i<D;i++){
            if(i) cout<<' ';
            cout<<answer[i];
        }
        cout<<"\n";
    }else{
        cout<<"No\n";
    }
}

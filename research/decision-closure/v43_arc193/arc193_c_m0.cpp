#include <bits/stdc++.h>
using namespace std;

struct VecHash{
    size_t operator()(vector<int> const& a) const noexcept{
        uint64_t h=1469598103934665603ULL;
        for(int x:a){ h^=(uint32_t)x+0x9e3779b9; h*=1099511628211ULL; }
        return (size_t)h;
    }
};
int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int H,W; long long C;
    if(!(cin>>H>>W>>C)) return 0;
    int M=H*W;
    vector<int> zero(M,0);
    unordered_set<vector<int>,VecHash> seen;
    queue<vector<int>> q;
    seen.insert(zero); q.push(zero);
    long long full=0;
    while(!q.empty()){
        auto a=move(q.front()); q.pop();
        bool ok=true;
        for(int x:a) if(x==0){ok=false;break;}
        if(ok) ++full;
        for(int r=0;r<H;r++) for(int col=0;col<W;col++){
            for(long long cc=1;cc<=C;cc++){
                vector<int> b=a;
                for(int j=0;j<W;j++) b[r*W+j]=(int)cc;
                for(int i=0;i<H;i++) b[i*W+col]=(int)cc;
                if(seen.insert(b).second) q.push(move(b));
            }
        }
    }
    cout<<(full%998244353LL)<<"\n";
}

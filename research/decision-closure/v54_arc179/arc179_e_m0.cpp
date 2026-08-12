#include <bits/stdc++.h>
using namespace std;
using int64 = long long;

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int N;
    if(!(cin>>N)) return 0;
    vector<int64> H(N),W(N);
    for(int i=0;i<N;i++) cin>>H[i]>>W[i];

    long long ans=0;
    for(int l=0;l<N;l++){
        vector<pair<int64,int64>> states;
        states.push_back({H[l],W[l]});
        ans++;

        for(int r=l+1;r<N;r++){
            vector<pair<int64,int64>> nxt;
            for(auto [h,w]:states){
                if(h==H[r]) nxt.push_back({h,w+W[r]});
                if(w==W[r]) nxt.push_back({h+H[r],w});
            }
            if(nxt.empty()) break;
            sort(nxt.begin(),nxt.end());
            nxt.erase(unique(nxt.begin(),nxt.end()),nxt.end());
            states.swap(nxt);
            ans++;
        }
    }

    cout<<ans<<'\n';
    return 0;
}

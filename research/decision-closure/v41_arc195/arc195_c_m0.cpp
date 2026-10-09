#include <bits/stdc++.h>
using namespace std;

struct Item{
    char p;
    long long x,y;
};

int main(){
    ios::sync_with_stdio(false);
    cin.tie(nullptr);
    int T;
    cin>>T;
    const long long SHIFT=300000;
    while(T--){
        int R,B;
        cin>>R>>B;
        if(R%2==1 || (R==0 && B%2==1)){
            cout<<"No\n";
            continue;
        }
        vector<pair<long long,long long>> v;
        vector<char> lab;
        auto add_edge=[&](char p, pair<long long,long long> nxt){
            lab.push_back(p);
            v.push_back(nxt);
        };
        v.push_back({0,0});
        if(R==0){
            if(B==2){
                add_edge('B',{1,1});
                lab.push_back('B');
            }else{
                int half=B/2;
                int a=1,b=half-1;
                int u=0,w=0;
                for(int i=0;i<a;i++){ lab.push_back('B'); ++u; v.push_back({u+w,u-w}); }
                for(int i=0;i<b;i++){ lab.push_back('B'); ++w; v.push_back({u+w,u-w}); }
                for(int i=0;i<a;i++){ lab.push_back('B'); --u; v.push_back({u+w,u-w}); }
                for(int i=0;i<b-1;i++){ lab.push_back('B'); --w; v.push_back({u+w,u-w}); }
                lab.push_back('B'); // final step returns to the first vertex
            }
        }else{
            int k=(R-2)/2;
            for(int j=1;j<=k;j++) add_edge('R',{0,-j});
            add_edge('R',{1,-k});
            for(int j=k-1;j>=0;j--) add_edge('R',{1,-j});
            // We are now at (1,0); replace the last duplicated append if k=0? No:
            // the construction above appends (1,0) exactly once.
            if(B>0){
                int a=0,b=0;
                auto abxy=[&](int aa,int bb){
                    return make_pair((long long)aa+bb+1,(long long)aa-bb);
                };
                if(B%2==1){
                    int m=(B-1)/2;
                    for(int i=0;i<m;i++){ lab.push_back('B'); ++a; v.push_back(abxy(a,b)); }
                    lab.push_back('B'); --b; v.push_back(abxy(a,b));
                    for(int i=0;i<m;i++){ lab.push_back('B'); --a; v.push_back(abxy(a,b)); }
                }else{
                    int m=B/2;
                    for(int i=0;i<m-1;i++){ lab.push_back('B'); ++a; v.push_back(abxy(a,b)); }
                    lab.push_back('B'); --b; v.push_back(abxy(a,b));
                    for(int i=0;i<m;i++){ lab.push_back('B'); --a; v.push_back(abxy(a,b)); }
                }
            }
            lab.push_back('R'); // endpoint -> (0,0)
        }

        int n=R+B;
        if((int)v.size()!=n || (int)lab.size()!=n){
            // Defensive impossibility marker; this branch should be unreachable.
            cout<<"No\n";
            continue;
        }
        cout<<"Yes\n";
        for(int i=0;i<n;i++){
            cout<<lab[i]<<" "<<v[i].first+SHIFT<<" "<<v[i].second+SHIFT<<"\n";
        }
    }
    return 0;
}

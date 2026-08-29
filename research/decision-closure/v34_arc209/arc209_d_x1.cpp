#include <bits/stdc++.h>
using namespace std;

int main() {
    ios::sync_with_stdio(false);
    cin.tie(nullptr);

    int T;
    cin >> T;
    while (T--) {
        int N;
        cin >> N;
        vector<int> a(N + 1);
        set<int> unassigned;
        set<int> ones;
        set<pair<int,int>> assigned_by_value;

        for (int i = 1; i <= N; ++i) {
            cin >> a[i];
            if (a[i] == -1) {
                a[i] = 0;
                unassigned.insert(i);
            } else {
                assigned_by_value.insert({a[i], i});
                if (a[i] == 1) ones.insert(i);
            }
        }

        vector<int> b(N + 1);

        auto assign_value = [&](int idx, int val) {
            if (a[idx] != 0) return;
            unassigned.erase(idx);
            a[idx] = val;
            assigned_by_value.insert({val, idx});
            if (val == 1) ones.insert(idx);
        };

        for (int i = 1; i <= N; ++i) {
            if (a[i] != 0) {
                int j = a[i];
                if (a[j] == 0) assign_value(j, 1);
                b[i] = a[j];
                continue;
            }

            // X1: if a one-valued target already exists, reuse it.
            // Creating another one-valued target can prematurely fix that target
            // and worsen its own earlier lexicographic contribution.
            if (!ones.empty()) {
                int j = *ones.begin();
                assign_value(i, j);
                b[i] = 1;
                continue;
            }

            if (i == 1) {
                assign_value(i, 1);
                b[i] = 1;
                continue;
            }

            auto it = unassigned.begin();
            if (it != unassigned.end() && *it == i) ++it;
            if (it != unassigned.end()) {
                int j = *it;
                assign_value(j, 1);
                assign_value(i, j);
                b[i] = 1;
                continue;
            }

            pair<int,int> best = {i, i};
            if (!assigned_by_value.empty()) {
                auto q = *assigned_by_value.begin();
                best = min(best, {q.first, q.second});
            }
            int target = best.second;
            assign_value(i, target);
            b[i] = (target == i ? i : a[target]);
        }

        for (int i = 1; i <= N; ++i) {
            if (i > 1) cout << ' ';
            cout << b[i];
        }
        cout << '\n';
    }
    return 0;
}

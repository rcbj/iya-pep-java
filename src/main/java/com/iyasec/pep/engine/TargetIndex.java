// SPDX-FileCopyrightText: 2026 Iya CyberSecurity Solutions, LLC
// SPDX-License-Identifier: MIT
package com.iyasec.pep.engine;

import com.iyasec.pep.engine.Values.Value;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Children whose target cannot match are skipped. A child is keyed when one AnyOf is made only of
 * AllOfs that each hold an equality Match of a literal against the same designator (string, anyURI,
 * integer or boolean, not MustBePresent). A bag that fails to resolve skips nothing.
 */
final class TargetIndex {
    @FunctionalInterface
    interface Bags {
        Bag resolve(int designator);
    }

    private static final class Key {
        private final int kind;
        private final Object value;

        private Key(int kind, Object value) {
            this.kind = kind;
            this.value = value;
        }

        static Key of(Value value) {
            if (value instanceof Value.Str s) {
                return new Key(1, s.text());
            }
            if (value instanceof Value.AnyUri s) {
                return new Key(2, s.text());
            }
            if (value instanceof Value.Int i) {
                return new Key(3, i.value());
            }
            if (value instanceof Value.Bool b) {
                return new Key(4, b.value());
            }
            return null;
        }

        @Override
        public boolean equals(Object o) {
            return o instanceof Key other && kind == other.kind && value.equals(other.value);
        }

        @Override
        public int hashCode() {
            return 31 * kind + value.hashCode();
        }
    }

    private static final class Group {
        final int designator;
        final Map<Key, List<Integer>> byKey = new HashMap<>();
        final List<Integer> members = new ArrayList<>();

        Group(int designator) {
            this.designator = designator;
        }
    }

    private static final class Keying {
        final int designator;
        final List<Key> keys;

        Keying(int designator, List<Key> keys) {
            this.designator = designator;
            this.keys = keys;
        }
    }

    private final List<Group> groups;
    private final List<Integer> unkeyed;
    private final int len;

    private TargetIndex(List<Group> groups, List<Integer> unkeyed, int len) {
        this.groups = groups;
        this.unkeyed = unkeyed;
        this.len = len;
    }

    /** The designator and literal keys of a target's keyable AnyOf, if it has one. */
    private static Keying keysOf(List<List<List<Match>>> target) {
        for (List<List<Match>> anyOf : target) {
            Integer designator = null;
            List<Key> keys = new ArrayList<>(anyOf.size());
            boolean keyed = true;
            for (List<Match> allOf : anyOf) {
                Integer id = null;
                Key key = null;
                for (Match match : allOf) {
                    if (match.func.kind != Func.Kind.EQUAL) {
                        continue;
                    }
                    Type type = match.func.type;
                    if (type != Type.STRING && type != Type.ANY_URI && type != Type.INTEGER && type != Type.BOOLEAN) {
                        continue;
                    }
                    if (!(match.attribute instanceof Expr.DesignatorExpr designatorExpr) || designatorExpr.mustBePresent) {
                        continue;
                    }
                    if (!(match.literal instanceof Expr.Literal literal) || literal.bag.values.isEmpty()) {
                        continue;
                    }
                    key = Key.of(literal.bag.values.get(0));
                    if (key == null) {
                        continue;
                    }
                    id = designatorExpr.id;
                    break;
                }
                if (id == null) {
                    keyed = false;
                    break;
                }
                if (designator == null) {
                    designator = id;
                } else if (designator != id) {
                    keyed = false;
                    break;
                }
                keys.add(key);
            }
            if (keyed && designator != null) {
                return new Keying(designator, keys);
            }
        }
        return null;
    }

    /** An index over children's targets, or null when fewer than two children are keyed. */
    static TargetIndex build(List<List<List<List<Match>>>> targets) {
        List<Group> groups = new ArrayList<>();
        List<Integer> unkeyed = new ArrayList<>();
        int len = targets.size();
        for (int child = 0; child < len; child++) {
            Keying keying = keysOf(targets.get(child));
            if (keying == null) {
                unkeyed.add(child);
                continue;
            }
            Group group = null;
            for (Group candidate : groups) {
                if (candidate.designator == keying.designator) {
                    group = candidate;
                    break;
                }
            }
            if (group == null) {
                group = new Group(keying.designator);
                groups.add(group);
            }
            group.members.add(child);
            for (Key key : keying.keys) {
                List<Integer> children = group.byKey.computeIfAbsent(key, ignored -> new ArrayList<>());
                if (children.isEmpty() || children.get(children.size() - 1) != child) {
                    children.add(child);
                }
            }
        }
        int keyed = 0;
        for (Group group : groups) {
            keyed += group.members.size();
        }
        if (keyed < 2) {
            return null;
        }
        return new TargetIndex(groups, unkeyed, len);
    }

    /** The children a request must evaluate. A resolve failure includes the whole group. */
    boolean[] candidates(Bags bags) {
        boolean[] set = new boolean[len];
        for (int child : unkeyed) {
            set[child] = true;
        }
        for (Group group : groups) {
            try {
                Bag bag = bags.resolve(group.designator);
                for (Value value : bag.values) {
                    Key key = Key.of(value);
                    if (key == null) {
                        continue;
                    }
                    List<Integer> children = group.byKey.get(key);
                    if (children != null) {
                        for (int child : children) {
                            set[child] = true;
                        }
                    }
                }
            } catch (Indet error) {
                for (int child : group.members) {
                    set[child] = true;
                }
            }
        }
        return set;
    }
}

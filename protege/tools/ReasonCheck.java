import java.io.File;
import java.util.LinkedHashMap;
import java.util.Map;

import org.semanticweb.HermiT.Configuration;
import org.semanticweb.HermiT.Reasoner;
import org.semanticweb.owlapi.apibinding.OWLManager;
import org.semanticweb.owlapi.model.*;
import org.semanticweb.owlapi.profiles.OWL2DLProfile;
import org.semanticweb.owlapi.profiles.OWLProfileReport;
import org.semanticweb.owlapi.reasoner.InferenceType;
import org.semanticweb.owlapi.reasoner.OWLReasoner;
import org.semanticweb.owlapi.util.InferredOntologyGenerator;

/**
 * Headless Protégé reasoning check.
 *
 * Uses the exact OWL API (4.5.29) and HermiT (1.4.3.456) jars shipped inside
 * D:\tools\Protege-5.6.9, so the result is what the Protégé GUI would compute.
 *
 * Usage:
 *   java -cp "lib/*;." ReasonCheck <ontology.ttl> [inferred-output.owl]
 */
public class ReasonCheck {
    public static void main(String[] args) throws Exception {
        if (args.length < 1) {
            System.err.println("usage: ReasonCheck <ontology.ttl> [inferred-output.owl]");
            System.exit(2);
        }
        File in = new File(args[0]);
        long t0 = System.currentTimeMillis();

        OWLOntologyManager manager = OWLManager.createOWLOntologyManager();
        OWLOntology ontology = manager.loadOntologyFromOntologyDocument(in);

        int classCount = ontology.getClassesInSignature().size();
        int objPropCount = ontology.getObjectPropertiesInSignature().size();
        int dataPropCount = ontology.getDataPropertiesInSignature().size();
        int individualCount = ontology.getIndividualsInSignature().size();
        int axiomCount = ontology.getAxiomCount();
        int logicalAxiomCount = ontology.getLogicalAxiomCount();

        OWLProfileReport profile = new OWL2DLProfile().checkOntology(ontology);
        int vcount = 0;
        for (Object v : profile.getViolations()) {
            if (vcount++ < 5) System.err.println("PROFILE: " + v);
        }

        Configuration configuration = new Configuration();
        OWLReasoner reasoner = new Reasoner(configuration, ontology);
        reasoner.precomputeInferences(
                InferenceType.CLASS_HIERARCHY,
                InferenceType.CLASS_ASSERTIONS,
                InferenceType.OBJECT_PROPERTY_ASSERTIONS);

        boolean consistent = reasoner.isConsistent();
        int unsatisfiable = reasoner.getUnsatisfiableClasses().getEntitiesMinusBottom().size();

        // 统计“推理机新增”的类断言/对象属性断言：先收集断言集合，再收集
        // 推理后的集合，做差。不能拿“某属性的值个数”去比“该个体的全部断言数”，
        // 也不能把 owl:Thing 算进类型里（否则每个个体都会虚增 1 条）。
        java.util.Set<String> assertedTypes = new java.util.HashSet<>();
        for (OWLClassAssertionAxiom ax : ontology.getAxioms(AxiomType.CLASS_ASSERTION)) {
            if (ax.getIndividual().isNamed() && !ax.getClassExpression().isAnonymous()) {
                assertedTypes.add(ax.getIndividual().asOWLNamedIndividual().getIRI() + "|"
                        + ax.getClassExpression().asOWLClass().getIRI());
            }
        }
        java.util.Set<String> allTypes = new java.util.HashSet<>();
        for (OWLNamedIndividual ind : ontology.getIndividualsInSignature()) {
            for (OWLClass c : reasoner.getTypes(ind, false).getFlattened()) {
                if (c.isOWLThing()) continue;
                allTypes.add(ind.getIRI() + "|" + c.getIRI());
            }
        }
        allTypes.removeAll(assertedTypes);
        int inferredTypes = allTypes.size();

        java.util.Set<String> assertedEdges = new java.util.HashSet<>();
        for (OWLObjectPropertyAssertionAxiom ax
                : ontology.getAxioms(AxiomType.OBJECT_PROPERTY_ASSERTION)) {
            if (ax.getSubject().isNamed() && ax.getObject().isNamed()) {
                assertedEdges.add(ax.getSubject().asOWLNamedIndividual().getIRI() + "|"
                        + ax.getProperty().asOWLObjectProperty().getIRI() + "|"
                        + ax.getObject().asOWLNamedIndividual().getIRI());
            }
        }
        java.util.Set<String> allEdges = new java.util.HashSet<>();
        for (OWLObjectProperty prop : ontology.getObjectPropertiesInSignature()) {
            for (OWLNamedIndividual ind : ontology.getIndividualsInSignature()) {
                for (OWLNamedIndividual target
                        : reasoner.getObjectPropertyValues(ind, prop).getFlattened()) {
                    allEdges.add(ind.getIRI() + "|" + prop.getIRI() + "|" + target.getIRI());
                }
            }
        }
        allEdges.removeAll(assertedEdges);
        int inferredEdges = allEdges.size();
        long ms = System.currentTimeMillis() - t0;

        Map<String, Object> r = new LinkedHashMap<>();
        r.put("file", in.getAbsolutePath());
        r.put("consistent", consistent);
        r.put("unsatisfiable_classes", unsatisfiable);
        r.put("classes", classCount);
        r.put("object_properties", objPropCount);
        r.put("data_properties", dataPropCount);
        r.put("individuals", individualCount);
        r.put("axioms", axiomCount);
        r.put("logical_axioms", logicalAxiomCount);
        r.put("owl2_dl_profile", profile.isInProfile());
        r.put("profile_violations", profile.getViolations().size());
        r.put("inferred_class_assertions", inferredTypes);
        r.put("inferred_object_assertions", inferredEdges);
        r.put("reasoner_ms", ms);
        System.out.println(toJson(r));

        if (args.length > 1) {
            OWLOntology inferred = manager.createOntology(
                    IRI.create("http://kgcourse.org/inferred/" + in.getName()));
            manager.addAxioms(inferred, ontology.getAxioms());
            new InferredOntologyGenerator(reasoner)
                    .fillOntology(manager.getOWLDataFactory(), inferred);
            manager.saveOntology(inferred, IRI.create(new File(args[1]).toURI()));
            System.out.println("inferred_ontology=" + new File(args[1]).getAbsolutePath());
        }
        reasoner.dispose();
    }

    private static String toJson(Map<String, Object> m) {
        StringBuilder sb = new StringBuilder("{");
        boolean first = true;
        for (Map.Entry<String, Object> e : m.entrySet()) {
            if (!first) sb.append(", ");
            first = false;
            sb.append('"').append(e.getKey().replace("\"", "\\\"")).append("\": ");
            Object v = e.getValue();
            if (v instanceof String) sb.append('"').append(((String) v).replace("\\", "\\\\").replace("\"", "\\\"")).append('"');
            else sb.append(v);
        }
        return sb.append('}').toString();
    }
}

package com.cyberguard.incident.ai;

import com.cyberguard.incident.ai.AgentModels.Classification;
import com.cyberguard.incident.ai.AgentModels.PipelineResult;
import com.cyberguard.incident.ai.AgentModels.Response;
import com.cyberguard.incident.ai.AgentModels.Risk;
import com.cyberguard.incident.ai.agent.ResponseReportAgent;
import com.cyberguard.incident.ai.agent.RiskAssessmentAgent;
import com.cyberguard.incident.ai.agent.ThreatClassificationAgent;
import org.springframework.stereotype.Component;

/**
 * Chains the 3 agents in order. Each agent makes its own LLM call:
 *
 *   Agent 1 (classify)  --->  Agent 2 (risk)  --->  Agent 3 (actions + report)
 *
 * Output of each agent is the input of the next. No database access here.
 */
@Component
public class AgentPipeline {

    private final ThreatClassificationAgent classificationAgent;
    private final RiskAssessmentAgent riskAgent;
    private final ResponseReportAgent responseAgent;

    public AgentPipeline(ThreatClassificationAgent classificationAgent,
                         RiskAssessmentAgent riskAgent,
                         ResponseReportAgent responseAgent) {
        this.classificationAgent = classificationAgent;
        this.riskAgent = riskAgent;
        this.responseAgent = responseAgent;
    }

    public PipelineResult run(AnalysisContext ctx) {
        Classification classification = classificationAgent.run(ctx);
        Risk risk = riskAgent.run(ctx, classification);
        Response response = responseAgent.run(ctx, classification, risk);
        return new PipelineResult(classification, risk, response);
    }
}
